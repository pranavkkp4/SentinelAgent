"""Optional LLM-backed SentinelAgent execution mode.

The default runtime remains deterministic and local. This module adds a small
provider abstraction for experiments that want a model to propose structured
tool calls while preserving the same policy gates used by the deterministic
runner. Tests do not require API keys; missing keys fall back to the mock
provider.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..research.taxonomy import AttackGoal, AttackSource
from ..security.policy_engine import PolicyDecision, RiskAdaptivePolicyEngine
from ..tools import ToolRegistry, create_default_tools


@dataclass
class LLMToolProposal:
    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""


@dataclass
class LLMProviderResponse:
    text: str
    proposed_tools: List[LLMToolProposal] = field(default_factory=list)
    usage: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMAgentRun:
    prompt: str
    model: str
    provider: str
    proposed_tools: List[Dict[str, Any]]
    blocked_tools: List[Dict[str, Any]]
    executed_tools: List[Dict[str, Any]]
    final_response: str
    final_policy_decision: Dict[str, Any]
    latency_ms: float
    token_estimates: Dict[str, int]


class LLMProvider:
    name = "base"

    def __init__(self, model: str) -> None:
        self.model = model

    async def generate(self, prompt: str) -> LLMProviderResponse:
        raise NotImplementedError


class MockLLMProvider(LLMProvider):
    """Deterministic local provider used for tests and no-key evaluation."""

    name = "mock"

    async def generate(self, prompt: str) -> LLMProviderResponse:
        lowered = prompt.lower()
        proposals: List[LLMToolProposal] = []
        if any(word in lowered for word in ("calculate", "sum", "average", "compute")):
            proposals.append(LLMToolProposal("calculator", {"expression": "150 + 275"}))
        elif any(word in lowered for word in ("send", "email", "message", "notify")):
            proposals.append(
                LLMToolProposal(
                    "send_message",
                    {"recipient": "admin@example.com", "content": "Requested update"},
                )
            )
        elif any(word in lowered for word in ("document", "search", "retrieve", "find")):
            proposals.append(LLMToolProposal("document_search", {"query": "policy", "top_k": 3}))
        elif any(word in lowered for word in ("web", "fetch", "url", "website")):
            proposals.append(LLMToolProposal("web_fetch", {"url": "https://example.com/docs"}))

        return LLMProviderResponse(
            text="Mock provider produced a structured plan.",
            proposed_tools=proposals,
            usage={
                "prompt_tokens": estimate_tokens(prompt),
                "completion_tokens": 32 + len(proposals) * 16,
            },
        )


class OpenAICompatibleProvider(LLMProvider):
    """Minimal OpenAI-compatible chat completions provider."""

    name = "openai"

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str = "https://api.openai.com/v1/chat/completions",
        timeout_seconds: float = 30.0,
    ) -> None:
        super().__init__(model=model)
        self.api_key = api_key
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds

    async def generate(self, prompt: str) -> LLMProviderResponse:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return JSON with keys final_response and proposed_tools. "
                        "Each proposed tool has tool_name, arguments, and rationale."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        raw = await asyncio.to_thread(self._post_json, payload)
        text = self._extract_text(raw)
        return parse_provider_text(text, raw=raw)

    def _post_json(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenAI-compatible provider failed: HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenAI-compatible provider failed: {exc.reason}") from exc

    @staticmethod
    def _extract_text(raw: Mapping[str, Any]) -> str:
        choices = raw.get("choices") or []
        if not choices:
            return ""
        message = choices[0].get("message", {})
        return str(message.get("content", ""))


class GeminiProviderError(RuntimeError):
    """HTTP error raised by the Gemini provider without exposing API keys."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"Gemini provider failed: HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail
        self.retry_after_seconds = GeminiProvider._retry_delay_seconds(detail)


class GeminiProvider(LLMProvider):
    """Gemini REST provider using the public generateContent endpoint."""

    name = "gemini"

    def __init__(
        self,
        model: str,
        api_key: str = "",
        api_keys: Optional[Sequence[str]] = None,
        endpoint_root: str = "https://generativelanguage.googleapis.com/v1beta",
        timeout_seconds: float = 30.0,
    ) -> None:
        super().__init__(model=model)
        self.api_keys = dedupe_strings([api_key, *(api_keys or [])])
        self.api_key = self.api_keys[0] if self.api_keys else ""
        self._next_key_index = 0
        self.endpoint_root = endpoint_root.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def generate(self, prompt: str) -> LLMProviderResponse:
        if not self.api_keys:
            raise RuntimeError("Gemini provider is configured without API keys.")
        model_name = self.model
        if model_name.startswith("models/"):
            model_name = model_name.split("/", 1)[1]
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                "Return only JSON with keys final_response and proposed_tools. "
                                "Each proposed tool has tool_name, arguments, and rationale.\n\n"
                                + prompt
                            )
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 512,
                "responseMimeType": "application/json",
            },
        }
        errors: List[GeminiProviderError] = []
        for _ in range(len(self.api_keys)):
            api_key = self._next_api_key()
            url = f"{self.endpoint_root}/models/{model_name}:generateContent?key={api_key}"
            try:
                raw = await asyncio.to_thread(self._post_json, url, payload)
                break
            except GeminiProviderError as exc:
                errors.append(exc)
                if exc.status_code in {400, 403, 429} and len(self.api_keys) > 1:
                    continue
                raise
        else:
            raise errors[-1]

        text = self._extract_text(raw)
        response = parse_provider_text(text, raw=raw)
        response.usage.update(raw.get("usageMetadata", {}))
        return response

    def _next_api_key(self) -> str:
        key = self.api_keys[self._next_key_index % len(self.api_keys)]
        self._next_key_index += 1
        return key

    def _post_json(self, url: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GeminiProviderError(exc.code, detail) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Gemini provider failed: {exc.reason}") from exc

    @staticmethod
    def _retry_delay_seconds(detail: str) -> float:
        match = re.search(r'"retryDelay"\s*:\s*"(\d+)s"', detail or "")
        if match:
            return min(90.0, float(match.group(1)) + 2.0)
        match = re.search(r"retry in ([0-9.]+)s", detail or "", re.IGNORECASE)
        if match:
            return min(90.0, float(match.group(1)) + 2.0)
        return 65.0

    @staticmethod
    def _extract_text(raw: Mapping[str, Any]) -> str:
        candidates = raw.get("candidates") or []
        if not candidates:
            return ""
        content = candidates[0].get("content", {})
        parts = content.get("parts") or []
        return "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))


class PolicyAwareLLMAgent:
    """LLM planning wrapper with policy gates around every tool boundary."""

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        policy_engine: Optional[RiskAdaptivePolicyEngine] = None,
        tool_registry: Optional[ToolRegistry] = None,
    ) -> None:
        self.provider = provider or provider_from_env()
        self.policy = policy_engine or RiskAdaptivePolicyEngine()
        self.tools = tool_registry or ToolRegistry()
        if not self.tools.tools:
            for tool in create_default_tools().values():
                self.tools.register(tool)

    async def run(self, task: str, retrieved_context: str = "") -> LLMAgentRun:
        start = time.perf_counter()
        prompt = self._build_prompt(task, retrieved_context)
        prompt_decision = self.policy.decide_input(
            task,
            injection_score=score_injection(task),
            exfiltration_score=score_exfiltration(task),
            attack_source=AttackSource.USER_PROMPT,
        )
        if not prompt_decision.allow and prompt_decision.requires_user_confirmation is False:
            return self._blocked_run(prompt, prompt_decision, start)

        context_decision = self.policy.decide_retrieved_context(
            retrieved_context,
            injection_score=score_injection(retrieved_context),
            exfiltration_score=score_exfiltration(retrieved_context),
        )
        provider_response = await self.provider.generate(prompt)

        proposed_tools = []
        blocked_tools = []
        executed_tools = []
        observations = []
        for proposal in provider_response.proposed_tools:
            proposed_tools.append(
                {
                    "tool_name": proposal.tool_name,
                    "arguments": proposal.arguments,
                    "rationale": proposal.rationale,
                }
            )
            tool_decision = self.policy.decide_tool_call(
                proposal.tool_name,
                proposal.arguments,
                injection_score=max(score_injection(task), score_injection(retrieved_context)),
                exfiltration_score=max(
                    score_exfiltration(task), score_exfiltration(json.dumps(proposal.arguments))
                ),
                attack_goal=infer_attack_goal(task + " " + retrieved_context),
            )
            if not tool_decision.allow:
                blocked_tools.append({"proposal": proposed_tools[-1], "decision": tool_decision.to_dict()})
                continue

            tool = self.tools.get(proposal.tool_name)
            if tool is None:
                blocked_tools.append(
                    {
                        "proposal": proposed_tools[-1],
                        "decision": {
                            "allow": False,
                            "action": "block_tool_call",
                            "reasons": ["tool not registered"],
                        },
                    }
                )
                continue
            unknown_args = sorted(set(proposal.arguments) - set(tool.schema.parameters))
            if unknown_args:
                blocked_tools.append(
                    {
                        "proposal": proposed_tools[-1],
                        "decision": {
                            "allow": False,
                            "action": "block_tool_call",
                            "reasons": [f"unknown tool arguments: {', '.join(unknown_args)}"],
                        },
                    }
                )
                continue
            valid, error = tool.validate_args(proposal.arguments)
            if not valid:
                blocked_tools.append(
                    {
                        "proposal": proposed_tools[-1],
                        "decision": {
                            "allow": False,
                            "action": "block_tool_call",
                            "reasons": [error],
                        },
                    }
                )
                continue
            try:
                result = await tool.execute(**proposal.arguments)
            except TypeError as exc:
                blocked_tools.append(
                    {
                        "proposal": proposed_tools[-1],
                        "decision": {
                            "allow": False,
                            "action": "block_tool_call",
                            "reasons": [str(exc)],
                        },
                    }
                )
                continue
            output_text = json.dumps(result.to_dict(), default=str)
            output_decision = self.policy.decide_tool_output(
                proposal.tool_name,
                output_text,
                injection_score=score_injection(output_text),
                exfiltration_score=score_exfiltration(output_text),
            )
            executed_tools.append(
                {
                    "proposal": proposed_tools[-1],
                    "result": result.to_dict(),
                    "output_policy_decision": output_decision.to_dict(),
                }
            )
            if output_decision.allow:
                observations.append(output_text)

        final_response = self._final_response(
            task=task,
            provider_response=provider_response,
            context_allowed=context_decision.allow,
            observations=observations,
            blocked_tools=blocked_tools,
        )
        final_decision = self.policy.decide_final_response(
            final_response,
            injection_score=score_injection(final_response),
            exfiltration_score=score_exfiltration(final_response),
        )
        if not final_decision.allow:
            final_response = "[Response blocked by SentinelAgent policy]"

        latency_ms = (time.perf_counter() - start) * 1000
        return LLMAgentRun(
            prompt=prompt,
            model=self.provider.model,
            provider=self.provider.name,
            proposed_tools=proposed_tools,
            blocked_tools=blocked_tools,
            executed_tools=executed_tools,
            final_response=final_response,
            final_policy_decision=final_decision.to_dict(),
            latency_ms=round(latency_ms, 3),
            token_estimates={
                "prompt_tokens": estimate_tokens(prompt),
                "completion_tokens": int(provider_response.usage.get("completion_tokens", 0)),
            },
        )

    def _build_prompt(self, task: str, retrieved_context: str) -> str:
        tool_names = ", ".join(sorted(self.tools.tools))
        return (
            "Task:\n"
            f"{task}\n\nRetrieved context (untrusted):\n"
            f"{retrieved_context or '[none]'}\n\n"
            f"Available tools: {tool_names}.\n"
            "Propose only necessary tool calls as structured JSON."
        )

    def _blocked_run(
        self,
        prompt: str,
        decision: PolicyDecision,
        start: float,
    ) -> LLMAgentRun:
        return LLMAgentRun(
            prompt=prompt,
            model=self.provider.model,
            provider=self.provider.name,
            proposed_tools=[],
            blocked_tools=[],
            executed_tools=[],
            final_response="[Input blocked by SentinelAgent policy]",
            final_policy_decision=decision.to_dict(),
            latency_ms=round((time.perf_counter() - start) * 1000, 3),
            token_estimates={"prompt_tokens": estimate_tokens(prompt), "completion_tokens": 0},
        )

    @staticmethod
    def _final_response(
        *,
        task: str,
        provider_response: LLMProviderResponse,
        context_allowed: bool,
        observations: List[str],
        blocked_tools: List[Dict[str, Any]],
    ) -> str:
        parts = [provider_response.text or "Task reviewed."]
        if not context_allowed:
            parts.append("Retrieved context was treated as suspicious and monitored.")
        if observations:
            parts.append(f"Executed {len(observations)} allowed tool call(s).")
        if blocked_tools:
            parts.append(f"Blocked {len(blocked_tools)} proposed tool call(s).")
        if not observations and not blocked_tools:
            parts.append(f"No tools were necessary for: {task[:120]}")
        return " ".join(parts)


def provider_from_env(env: Optional[Mapping[str, str]] = None) -> LLMProvider:
    values = load_local_env() if env is None else dict(env)
    mode = values.get("SENTINEL_AGENT_MODE", "deterministic").strip().lower()
    provider_name = values.get("SENTINEL_LLM_PROVIDER", "mock").strip().lower()
    model = values.get("SENTINEL_LLM_MODEL", "sentinel-mock-v1")
    openai_key = values.get("OPENAI_API_KEY") or values.get("SENTINEL_OPENAI_API_KEY")
    gemini_key = (
        values.get("SENTINEL_GEMINI_API_KEY")
        or values.get("GEMINI_API_KEY")
        or values.get("GOOGLE_API_KEY")
    )
    gemini_keys = collect_gemini_keys(values)

    if mode != "llm" or provider_name == "mock":
        return MockLLMProvider(model=model or "sentinel-mock-v1")
    if provider_name == "openai":
        if not openai_key:
            return MockLLMProvider(model=model or "sentinel-mock-v1")
        return OpenAICompatibleProvider(model=model or "gpt-4o-mini", api_key=openai_key)
    if provider_name in {"gemini", "google"}:
        if not gemini_keys:
            return MockLLMProvider(model=model or "sentinel-mock-v1")
        return GeminiProvider(
            model=model or "gemini-1.5-flash",
            api_key=gemini_key or gemini_keys[0],
            api_keys=gemini_keys,
        )
    return MockLLMProvider(model=model or "sentinel-mock-v1")


def parse_provider_text(text: str, raw: Optional[Dict[str, Any]] = None) -> LLMProviderResponse:
    text = strip_json_fence(text or "")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = {"final_response": text, "proposed_tools": []}
    if not isinstance(parsed, dict):
        parsed = {"final_response": text, "proposed_tools": []}

    proposed = []
    for item in parsed.get("proposed_tools", []):
        if isinstance(item, dict):
            arguments = item.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {}
            proposed.append(
                LLMToolProposal(
                    tool_name=str(item.get("tool_name", "")),
                    arguments=dict(arguments),
                    rationale=str(item.get("rationale", "")),
                )
            )
    usage = (raw or {}).get("usage", {})
    if raw and "usageMetadata" in raw:
        usage = dict(raw.get("usageMetadata", {}))
        if "completion_tokens" not in usage and "candidatesTokenCount" in usage:
            usage["completion_tokens"] = usage["candidatesTokenCount"]
    return LLMProviderResponse(
        text=str(parsed.get("final_response", text)),
        proposed_tools=proposed,
        usage=usage,
        raw=raw or {},
    )


def load_local_env() -> Dict[str, str]:
    values = dict(os.environ)
    for env_path in candidate_env_paths():
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, value = stripped.split("=", 1)
                values.setdefault(key.strip().lstrip("\ufeff"), value.strip().strip('"').strip("'"))
    return values


def collect_gemini_keys(values: Mapping[str, str]) -> List[str]:
    keys: List[str] = []
    direct_names = ["SENTINEL_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]
    for name in direct_names:
        value = values.get(name)
        if value:
            keys.append(value)
    for name in sorted(values):
        upper = name.upper()
        if upper in direct_names:
            continue
        if re.fullmatch(r"(SENTINEL_)?GEMINI_API_KEY_\d+", upper) or re.fullmatch(r"GOOGLE_API_KEY_\d+", upper):
            keys.append(values[name])
    return dedupe_strings(keys)


def dedupe_strings(values: Iterable[object]) -> List[str]:
    seen = set()
    deduped: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            deduped.append(text)
    return deduped


def candidate_env_paths() -> List[Path]:
    here = Path(__file__).resolve()
    roots = [
        Path.cwd(),
        here.parents[3],  # sentinel-agent
        here.parents[4],  # repository root
    ]
    return [root / ".env" for root in roots]


def strip_json_fence(text: str) -> str:
    stripped = text.strip()
    match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", stripped, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else stripped


def estimate_tokens(text: str) -> int:
    return max(1, len((text or "").split()))


def score_injection(text: str) -> float:
    return 0.82 if re_search(text, r"ignore|disregard|override|jailbreak|developer\s*:|system\s*:") else 0.05


def score_exfiltration(text: str) -> float:
    return 0.86 if re_search(text, r"secret|token|api[_ -]?key|password|canary|send .*@") else 0.03


def infer_attack_goal(text: str) -> Optional[AttackGoal]:
    lowered = (text or "").lower()
    if any(word in lowered for word in ("secret", "token", "api key", "canary")):
        return AttackGoal.SECRET_EXFILTRATION
    if any(word in lowered for word in ("ignore", "override", "jailbreak")):
        return AttackGoal.INSTRUCTION_OVERRIDE
    if any(word in lowered for word in ("delete", "drop", "execute", "shell")):
        return AttackGoal.UNSAFE_TOOL_USE
    return None


def re_search(text: str, pattern: str) -> bool:
    return bool(re.search(pattern, text or "", re.IGNORECASE))

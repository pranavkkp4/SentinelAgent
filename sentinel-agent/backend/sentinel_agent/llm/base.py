"""Provider-neutral interfaces for optional LLM-backed evaluation.

The default SentinelAgent runtime is deterministic. These interfaces let tests,
benchmarks, or demos opt into a real provider through environment variables
without requiring provider SDKs or API keys for the normal path.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import os
from typing import Any, Dict, Mapping, Optional, Sequence


@dataclass(frozen=True)
class LLMMessage:
    """A chat-style message passed to an LLM adapter."""

    role: str
    content: str

    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True)
class LLMRequest:
    """Request payload shared by all LLM adapters."""

    prompt: str = ""
    system_prompt: str = ""
    messages: Sequence[LLMMessage] = ()
    temperature: float = 0.0
    max_tokens: int = 512
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def normalized_messages(self) -> list[LLMMessage]:
        """Return a chat message list, including prompt fields when supplied."""
        normalized = list(self.messages)
        if self.system_prompt:
            normalized.insert(0, LLMMessage(role="system", content=self.system_prompt))
        if self.prompt:
            normalized.append(LLMMessage(role="user", content=self.prompt))
        return normalized


@dataclass(frozen=True)
class AdapterStatus:
    """Runtime availability for a configured LLM adapter."""

    provider: str
    model: str
    enabled: bool
    available: bool
    reason: str = ""
    requires_api_key: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "enabled": self.enabled,
            "available": self.available,
            "reason": self.reason,
            "requires_api_key": self.requires_api_key,
        }


@dataclass(frozen=True)
class LLMResponse:
    """Response returned by an LLM adapter."""

    text: str
    provider: str
    model: str
    skipped: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)
    raw: Optional[Mapping[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "provider": self.provider,
            "model": self.model,
            "skipped": self.skipped,
            "metadata": dict(self.metadata),
            "raw": dict(self.raw) if self.raw is not None else None,
        }


class LLMAdapterError(RuntimeError):
    """Base error for LLM adapter failures."""


class LLMUnavailableError(LLMAdapterError):
    """Raised when a real adapter is selected but not usable."""


class LLMAdapter(ABC):
    """Abstract adapter implemented by deterministic and real providers."""

    provider = "base"
    requires_api_key = False

    def __init__(self, model: str, enabled: bool = True):
        self.model = model
        self.enabled = enabled

    def status(self) -> AdapterStatus:
        available = self.enabled
        return AdapterStatus(
            provider=self.provider,
            model=self.model,
            enabled=self.enabled,
            available=available,
            reason="" if available else "disabled",
            requires_api_key=self.requires_api_key,
        )

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate a response or raise an adapter error."""

    async def maybe_generate(self, request: LLMRequest) -> LLMResponse:
        """Generate when available, otherwise return a skipped response.

        This is the method benchmarks should call so missing API keys or local
        endpoints do not fail deterministic test runs.
        """
        status = self.status()
        if not status.available:
            return self._skipped_response(status.reason)

        try:
            return await self.generate(request)
        except Exception as exc:  # pragma: no cover - depends on external services.
            return self._skipped_response(str(exc))

    def _skipped_response(self, reason: str) -> LLMResponse:
        return LLMResponse(
            text="",
            provider=self.provider,
            model=self.model,
            skipped=True,
            metadata={"skip_reason": reason or "unavailable"},
        )


class DeterministicLLMAdapter(LLMAdapter):
    """Offline adapter used by tests and deterministic benchmarks."""

    provider = "deterministic"

    def __init__(self, model: str = "deterministic-orchestrator", enabled: bool = True):
        super().__init__(model=model, enabled=enabled)

    async def generate(self, request: LLMRequest) -> LLMResponse:
        text = request.prompt or "\n".join(message.content for message in request.normalized_messages())
        return LLMResponse(
            text=f"[deterministic] {text[:512]}",
            provider=self.provider,
            model=self.model,
            skipped=False,
            metadata={"mode": "offline_reproducible"},
        )


class EnvKeyedLLMAdapter(LLMAdapter):
    """Provider adapter that becomes available only when its API key exists."""

    requires_api_key = True

    def __init__(
        self,
        provider: str,
        model: str,
        api_key_env: str,
        enabled: bool = True,
    ):
        super().__init__(model=model, enabled=enabled)
        self.provider = provider
        self.api_key_env = api_key_env

    def status(self) -> AdapterStatus:
        if not self.enabled:
            return AdapterStatus(
                provider=self.provider,
                model=self.model,
                enabled=False,
                available=False,
                reason="disabled",
                requires_api_key=True,
            )
        if not os.getenv(self.api_key_env):
            return AdapterStatus(
                provider=self.provider,
                model=self.model,
                enabled=True,
                available=False,
                reason=f"missing {self.api_key_env}",
                requires_api_key=True,
            )
        return AdapterStatus(
            provider=self.provider,
            model=self.model,
            enabled=True,
            available=True,
            reason="adapter interface configured; provider SDK/client is intentionally optional",
            requires_api_key=True,
        )

    async def generate(self, request: LLMRequest) -> LLMResponse:
        status = self.status()
        if not status.available:
            raise LLMUnavailableError(status.reason)
        return LLMResponse(
            text="",
            provider=self.provider,
            model=self.model,
            skipped=True,
            metadata={
                "skip_reason": (
                    "provider adapter interface is configured, but no hard SDK "
                    "dependency is bundled in the reproducible artifact"
                ),
                "message_count": len(request.normalized_messages()),
            },
        )


class LocalModelAdapter(LLMAdapter):
    """Local model interface guarded by an explicit endpoint or command env var."""

    provider = "local"

    def __init__(self, model: str = "local-model", enabled: bool = True):
        super().__init__(model=model, enabled=enabled)
        self.endpoint = os.getenv("SENTINEL_LOCAL_MODEL_URL", "")
        self.command = os.getenv("SENTINEL_LOCAL_MODEL_COMMAND", "")

    def status(self) -> AdapterStatus:
        if not self.enabled:
            return AdapterStatus(self.provider, self.model, False, False, "disabled")
        if not (self.endpoint or self.command):
            return AdapterStatus(
                self.provider,
                self.model,
                True,
                False,
                "missing SENTINEL_LOCAL_MODEL_URL or SENTINEL_LOCAL_MODEL_COMMAND",
            )
        return AdapterStatus(
            self.provider,
            self.model,
            True,
            False,
            "local model hook declared but execution is skipped in tests",
        )

    async def generate(self, request: LLMRequest) -> LLMResponse:
        return self._skipped_response(self.status().reason)


def get_llm_adapter(provider: str | None = None, model: str | None = None) -> LLMAdapter:
    """Return an adapter selected by arguments or SENTINEL_LLM_PROVIDER."""
    selected = (provider or os.getenv("SENTINEL_LLM_PROVIDER") or "deterministic").lower()
    if selected == "openai":
        return EnvKeyedLLMAdapter("openai", model or os.getenv("SENTINEL_OPENAI_MODEL", "gpt-4o-mini"), "OPENAI_API_KEY")
    if selected == "anthropic":
        return EnvKeyedLLMAdapter("anthropic", model or os.getenv("SENTINEL_ANTHROPIC_MODEL", "claude-3-5-haiku-latest"), "ANTHROPIC_API_KEY")
    if selected in {"gemini", "google"}:
        return EnvKeyedLLMAdapter("gemini", model or os.getenv("SENTINEL_GEMINI_MODEL", "gemini-1.5-flash"), "GEMINI_API_KEY")
    if selected == "local":
        return LocalModelAdapter(model or os.getenv("SENTINEL_LOCAL_MODEL", "local-model"))
    return DeterministicLLMAdapter(model or "deterministic-orchestrator")


def get_llm_adapter_statuses() -> Dict[str, Dict[str, Any]]:
    """Return availability for all supported optional adapters."""
    return {
        name: get_llm_adapter(name).status().to_dict()
        for name in ["deterministic", "openai", "anthropic", "gemini", "local"]
    }

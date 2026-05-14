"""Optional LLM adapters for SentinelAgent evaluation.

Adapters use the Python standard library HTTP client so provider SDKs remain
optional. Real network calls only happen when an adapter is explicitly enabled
and ``generate`` is called.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import urllib.error
import urllib.request
from typing import Any, Dict, Mapping, Optional

from .base import (
    AdapterStatus,
    LLMAdapter,
    LLMAdapterError,
    LLMRequest,
    LLMResponse,
    LLMUnavailableError,
)


def _post_json(
    url: str,
    headers: Mapping[str, str],
    payload: Mapping[str, Any],
    timeout_seconds: float,
) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers=dict(headers),
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMAdapterError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMAdapterError(f"Network error: {exc.reason}") from exc

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise LLMAdapterError("Provider returned invalid JSON") from exc

    if not isinstance(parsed, dict):
        raise LLMAdapterError("Provider returned an unexpected JSON payload")
    return parsed


def _messages_as_dicts(request: LLMRequest) -> list[Dict[str, str]]:
    return [message.to_dict() for message in request.normalized_messages()]


def _combine_messages(request: LLMRequest) -> str:
    lines = []
    for message in request.normalized_messages():
        lines.append(f"{message.role}: {message.content}")
    return "\n".join(lines)


class DeterministicLLMAdapter(LLMAdapter):
    """Stable local adapter used by default for deterministic tests."""

    provider = "deterministic"
    requires_api_key = False

    def __init__(self, model: str = "sentinel-deterministic-v1", enabled: bool = True):
        super().__init__(model=model, enabled=enabled)

    async def generate(self, request: LLMRequest) -> LLMResponse:
        prompt = _combine_messages(request)
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:12]
        last_user = next(
            (
                message.content
                for message in reversed(request.normalized_messages())
                if message.role == "user"
            ),
            prompt,
        )
        text = f"Deterministic adapter response {digest}: {last_user[:500]}"
        return LLMResponse(
            text=text,
            provider=self.provider,
            model=self.model,
            metadata={"deterministic": True},
        )


class _HTTPAdapter(LLMAdapter):
    """Base class for JSON-over-HTTP provider adapters."""

    default_endpoint = ""
    default_model = ""
    api_key_env_name = ""
    requires_api_key = True

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout_seconds: float = 30.0,
        enabled: bool = True,
    ):
        super().__init__(model=model or self.default_model, enabled=enabled)
        self.api_key = api_key or ""
        self.endpoint = endpoint or self.default_endpoint
        self.timeout_seconds = timeout_seconds

    def status(self) -> AdapterStatus:
        if not self.enabled:
            available = False
            reason = "disabled"
        elif self.requires_api_key and not self.api_key:
            available = False
            reason = f"missing {self.api_key_env_name}"
        elif not self.endpoint:
            available = False
            reason = "missing endpoint"
        else:
            available = True
            reason = ""

        return AdapterStatus(
            provider=self.provider,
            model=self.model,
            enabled=self.enabled,
            available=available,
            reason=reason,
            requires_api_key=self.requires_api_key,
        )

    def _ensure_available(self) -> None:
        status = self.status()
        if not status.available:
            raise LLMUnavailableError(status.reason)


class OpenAIAdapter(_HTTPAdapter):
    """OpenAI chat-completions adapter."""

    provider = "openai"
    default_endpoint = "https://api.openai.com/v1/chat/completions"
    default_model = "gpt-4o-mini"
    api_key_env_name = "SENTINEL_OPENAI_API_KEY or OPENAI_API_KEY"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self._ensure_available()
        payload = {
            "model": self.model,
            "messages": _messages_as_dicts(request),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        raw = await asyncio.to_thread(
            _post_json,
            self.endpoint,
            headers,
            payload,
            self.timeout_seconds,
        )
        choices = raw.get("choices") or []
        message = choices[0].get("message", {}) if choices else {}
        return LLMResponse(
            text=str(message.get("content", "")),
            provider=self.provider,
            model=self.model,
            metadata={"usage": raw.get("usage", {})},
            raw=raw,
        )


class AnthropicAdapter(_HTTPAdapter):
    """Anthropic messages API adapter."""

    provider = "anthropic"
    default_endpoint = "https://api.anthropic.com/v1/messages"
    default_model = "claude-3-haiku-20240307"
    api_key_env_name = "SENTINEL_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self._ensure_available()
        system_parts = []
        messages = []
        for message in request.normalized_messages():
            if message.role == "system":
                system_parts.append(message.content)
            else:
                role = "assistant" if message.role == "assistant" else "user"
                messages.append({"role": role, "content": message.content})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        raw = await asyncio.to_thread(
            _post_json,
            self.endpoint,
            headers,
            payload,
            self.timeout_seconds,
        )
        text_parts = [
            str(part.get("text", ""))
            for part in raw.get("content", [])
            if isinstance(part, dict) and part.get("type") == "text"
        ]
        return LLMResponse(
            text="".join(text_parts),
            provider=self.provider,
            model=self.model,
            metadata={"usage": raw.get("usage", {})},
            raw=raw,
        )


class GeminiAdapter(_HTTPAdapter):
    """Google Gemini generateContent adapter."""

    provider = "gemini"
    default_endpoint = "https://generativelanguage.googleapis.com/v1beta/models"
    default_model = "gemini-1.5-flash"
    api_key_env_name = "SENTINEL_GEMINI_API_KEY, GEMINI_API_KEY, or GOOGLE_API_KEY"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self._ensure_available()
        endpoint = self.endpoint.rstrip("/")
        if ":generateContent" not in endpoint:
            endpoint = f"{endpoint}/{self.model}:generateContent"
        separator = "&" if "?" in endpoint else "?"
        url = f"{endpoint}{separator}key={self.api_key}"
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": _combine_messages(request)}],
                }
            ],
            "generationConfig": {
                "temperature": request.temperature,
                "maxOutputTokens": request.max_tokens,
            },
        }
        headers = {"Content-Type": "application/json"}
        raw = await asyncio.to_thread(_post_json, url, headers, payload, self.timeout_seconds)
        candidates = raw.get("candidates") or []
        content = candidates[0].get("content", {}) if candidates else {}
        parts = content.get("parts") or []
        text = "".join(
            str(part.get("text", ""))
            for part in parts
            if isinstance(part, dict)
        )
        return LLMResponse(
            text=text,
            provider=self.provider,
            model=self.model,
            metadata={"usage": raw.get("usageMetadata", {})},
            raw=raw,
        )


class LocalModelAdapter(_HTTPAdapter):
    """OpenAI-compatible local model endpoint adapter stub.

    Set ``SENTINEL_LLM_BASE_URL`` or ``SENTINEL_LOCAL_LLM_URL`` to a local
    chat-completions endpoint. If the URL is a server root, ``/v1/chat/completions``
    is appended automatically.
    """

    provider = "local"
    default_endpoint = ""
    default_model = "local-model"
    api_key_env_name = "SENTINEL_LOCAL_LLM_API_KEY"
    requires_api_key = False

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout_seconds: float = 30.0,
        enabled: bool = True,
    ):
        super().__init__(
            model=model,
            api_key=api_key,
            endpoint=self._normalize_endpoint(endpoint or ""),
            timeout_seconds=timeout_seconds,
            enabled=enabled,
        )

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self._ensure_available()
        payload = {
            "model": self.model,
            "messages": _messages_as_dicts(request),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        raw = await asyncio.to_thread(
            _post_json,
            self.endpoint,
            headers,
            payload,
            self.timeout_seconds,
        )
        choices = raw.get("choices") or []
        message = choices[0].get("message", {}) if choices else {}
        return LLMResponse(
            text=str(message.get("content", "")),
            provider=self.provider,
            model=self.model,
            metadata={"usage": raw.get("usage", {})},
            raw=raw,
        )

    def status(self) -> AdapterStatus:
        status = super().status()
        if not self.endpoint and self.enabled:
            return AdapterStatus(
                provider=self.provider,
                model=self.model,
                enabled=self.enabled,
                available=False,
                reason="missing SENTINEL_LLM_BASE_URL or SENTINEL_LOCAL_LLM_URL",
                requires_api_key=False,
            )
        return status

    def _normalize_endpoint(self, endpoint: str) -> str:
        endpoint = endpoint.strip().rstrip("/")
        if not endpoint:
            return ""
        if endpoint.endswith("/v1/chat/completions") or endpoint.endswith("/chat/completions"):
            return endpoint
        return f"{endpoint}/v1/chat/completions"

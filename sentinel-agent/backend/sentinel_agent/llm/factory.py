"""Environment-driven LLM adapter factory."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

from .adapters import (
    AnthropicAdapter,
    DeterministicLLMAdapter,
    GeminiAdapter,
    LocalModelAdapter,
    OpenAIAdapter,
)
from .base import LLMAdapter


TRUE_VALUES = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class LLMAdapterSettings:
    """Settings used to construct an LLM adapter."""

    enabled: bool = False
    provider: str = "deterministic"
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    timeout_seconds: float = 30.0
    temperature: float = 0.0
    max_tokens: int = 512


def settings_from_env(env: Optional[Mapping[str, str]] = None) -> LLMAdapterSettings:
    """Build adapter settings from environment variables."""
    values = os.environ if env is None else env
    provider = _normalize_provider(values.get("SENTINEL_LLM_PROVIDER", "deterministic"))
    enabled = _env_bool(values, "SENTINEL_ENABLE_LLM_EVAL", default=False)

    return LLMAdapterSettings(
        enabled=enabled,
        provider=provider,
        model=_first_env(
            values,
            f"SENTINEL_{provider.upper()}_MODEL",
            _provider_specific_name(provider, "MODEL"),
            "SENTINEL_LLM_MODEL",
        ),
        base_url=_first_env(
            values,
            f"SENTINEL_{provider.upper()}_BASE_URL",
            _provider_specific_name(provider, "BASE_URL"),
            "SENTINEL_LLM_BASE_URL",
            "SENTINEL_LOCAL_LLM_URL",
        ),
        api_key=_api_key_from_env(provider, values),
        timeout_seconds=_env_float(values, "SENTINEL_LLM_TIMEOUT_SECONDS", 30.0),
        temperature=_env_float(values, "SENTINEL_LLM_TEMPERATURE", 0.0),
        max_tokens=_env_int(values, "SENTINEL_LLM_MAX_TOKENS", 512),
    )


def create_llm_adapter(
    settings: Optional[LLMAdapterSettings] = None,
    env: Optional[Mapping[str, str]] = None,
) -> LLMAdapter:
    """Create the configured adapter.

    Deterministic mode is returned unless ``SENTINEL_ENABLE_LLM_EVAL`` is true
    and a supported non-deterministic provider is selected.
    """
    resolved = settings or settings_from_env(env)
    provider = _normalize_provider(resolved.provider)

    if not resolved.enabled or provider == "deterministic":
        return DeterministicLLMAdapter(enabled=True)

    if provider == "openai":
        return OpenAIAdapter(
            model=resolved.model,
            api_key=resolved.api_key,
            endpoint=resolved.base_url,
            timeout_seconds=resolved.timeout_seconds,
            enabled=resolved.enabled,
        )
    if provider == "anthropic":
        return AnthropicAdapter(
            model=resolved.model,
            api_key=resolved.api_key,
            endpoint=resolved.base_url,
            timeout_seconds=resolved.timeout_seconds,
            enabled=resolved.enabled,
        )
    if provider == "gemini":
        return GeminiAdapter(
            model=resolved.model,
            api_key=resolved.api_key,
            endpoint=resolved.base_url,
            timeout_seconds=resolved.timeout_seconds,
            enabled=resolved.enabled,
        )
    if provider == "local":
        return LocalModelAdapter(
            model=resolved.model,
            api_key=resolved.api_key,
            endpoint=resolved.base_url,
            timeout_seconds=resolved.timeout_seconds,
            enabled=resolved.enabled,
        )

    raise ValueError(f"Unsupported SENTINEL_LLM_PROVIDER: {resolved.provider}")


def _api_key_from_env(provider: str, env: Mapping[str, str]) -> Optional[str]:
    key_names = {
        "openai": ("SENTINEL_OPENAI_API_KEY", "OPENAI_API_KEY"),
        "anthropic": ("SENTINEL_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
        "gemini": ("SENTINEL_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "local": ("SENTINEL_LOCAL_LLM_API_KEY",),
    }.get(provider, ())
    return _first_env(env, *key_names)


def _provider_specific_name(provider: str, suffix: str) -> str:
    provider_name = "GOOGLE" if provider == "gemini" else provider.upper()
    return f"SENTINEL_{provider_name}_{suffix}"


def _normalize_provider(provider: Optional[str]) -> str:
    value = (provider or "deterministic").strip().lower()
    aliases = {
        "": "deterministic",
        "none": "deterministic",
        "off": "deterministic",
        "mock": "deterministic",
        "google": "gemini",
        "google-gemini": "gemini",
        "ollama": "local",
        "llama.cpp": "local",
        "openai-compatible": "local",
    }
    return aliases.get(value, value)


def _first_env(env: Mapping[str, str], *names: str) -> Optional[str]:
    for name in names:
        value = env.get(name)
        if value:
            return value
    return None


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    value = env.get(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def _env_float(env: Mapping[str, str], name: str, default: float) -> float:
    value = env.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    value = env.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default

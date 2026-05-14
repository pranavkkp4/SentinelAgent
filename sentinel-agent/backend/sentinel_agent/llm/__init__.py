"""Optional LLM adapter package for SentinelAgent.

The package is safe to import without provider SDKs or API keys. By default,
``create_llm_adapter`` returns the deterministic adapter. Real adapters require
``SENTINEL_ENABLE_LLM_EVAL=true`` plus a supported provider selection.
"""

from .adapters import (
    AnthropicAdapter,
    DeterministicLLMAdapter,
    GeminiAdapter,
    LocalModelAdapter,
    OpenAIAdapter,
)
from .base import (
    AdapterStatus,
    LLMAdapter,
    LLMAdapterError,
    LLMMessage,
    LLMRequest,
    LLMResponse,
    LLMUnavailableError,
)
from .evaluation import LLMEvaluationAdapter, LLMEvaluationRequest, LLMEvaluationResult
from .factory import LLMAdapterSettings, create_llm_adapter, settings_from_env

__all__ = [
    "AdapterStatus",
    "AnthropicAdapter",
    "DeterministicLLMAdapter",
    "GeminiAdapter",
    "LLMAdapter",
    "LLMAdapterError",
    "LLMAdapterSettings",
    "LLMEvaluationAdapter",
    "LLMEvaluationRequest",
    "LLMEvaluationResult",
    "LLMMessage",
    "LLMRequest",
    "LLMResponse",
    "LLMUnavailableError",
    "LocalModelAdapter",
    "OpenAIAdapter",
    "create_llm_adapter",
    "settings_from_env",
]

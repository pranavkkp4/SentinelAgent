"""Tests for optional LLM adapter behavior."""

import asyncio

from sentinel_agent.llm import LLMAdapterSettings, LLMRequest, create_llm_adapter


def test_default_llm_adapter_is_deterministic_without_api_keys():
    adapter = create_llm_adapter(
        env={
            "SENTINEL_ENABLE_LLM_EVAL": "false",
            "SENTINEL_LLM_PROVIDER": "openai",
        }
    )
    status = adapter.status()
    response = asyncio.run(adapter.maybe_generate(LLMRequest(prompt="Hello")))

    assert status.provider == "deterministic"
    assert status.available is True
    assert status.requires_api_key is False
    assert response.skipped is False
    assert response.provider == "deterministic"
    assert "Hello" in response.text


def test_real_provider_without_api_key_skips_gracefully():
    adapter = create_llm_adapter(
        LLMAdapterSettings(
            enabled=True,
            provider="openai",
            api_key=None,
        )
    )
    status = adapter.status()
    response = asyncio.run(adapter.maybe_generate(LLMRequest(prompt="Should not call network")))

    assert status.provider == "openai"
    assert status.available is False
    assert status.requires_api_key is True
    assert status.reason.startswith("missing ")
    assert "OPENAI_API_KEY" in status.reason
    assert response.skipped is True
    assert response.text == ""
    assert response.metadata["skip_reason"] == status.reason


def test_local_provider_without_endpoint_skips_without_requiring_api_key():
    adapter = create_llm_adapter(
        LLMAdapterSettings(
            enabled=True,
            provider="local",
            api_key=None,
            base_url=None,
        )
    )
    status = adapter.status()
    response = asyncio.run(adapter.maybe_generate(LLMRequest(prompt="Local unavailable")))

    assert status.provider == "local"
    assert status.available is False
    assert status.requires_api_key is False
    assert "SENTINEL_LLM_BASE_URL" in status.reason
    assert response.skipped is True
    assert "SENTINEL_LOCAL_LLM_URL" in response.metadata["skip_reason"]

"""Tests for pegase.ai.providers: the multi-provider LLM abstraction.

Every real network call is mocked via httpx.MockTransport - nothing in this
file reaches a real LLM API.
"""

from __future__ import annotations

import httpx
import pytest

from pegase.ai.providers import (
    AnthropicProvider,
    OfflineProvider,
    OllamaProvider,
    OpenAIProvider,
    available_providers,
    get_provider,
)
from pegase.core.config import Settings


def _patch_client(monkeypatch, handler) -> None:
    class _Patched(httpx.AsyncClient):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.ai.providers.httpx.AsyncClient", _Patched)


def test_available_providers_lists_all():
    assert available_providers() == ["anthropic", "offline", "ollama", "openai"]


@pytest.mark.asyncio
async def test_offline_provider_never_calls_network():
    p = OfflineProvider()
    assert p.offline is True
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is False
    assert resp.text == ""


@pytest.mark.asyncio
async def test_anthropic_provider_success(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "sk-test"
        return httpx.Response(
            200,
            json={"content": [{"type": "text", "text": "hello "}, {"type": "text", "text": "world"}]},
        )

    _patch_client(monkeypatch, handler)
    p = AnthropicProvider(api_key="sk-test")
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is True
    assert resp.text == "hello world"
    assert resp.provider == "anthropic"
    assert p.offline is False


@pytest.mark.asyncio
async def test_openai_provider_success(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer sk-test"
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "an answer"}}]}
        )

    _patch_client(monkeypatch, handler)
    p = OpenAIProvider(api_key="sk-test")
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is True
    assert resp.text == "an answer"


@pytest.mark.asyncio
async def test_openai_provider_uses_base_url_override(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    _patch_client(monkeypatch, handler)
    p = OpenAIProvider(api_key="k", base_url="https://gateway.internal/v1")
    await p.complete(system="s", prompt="p")
    assert seen["url"] == "https://gateway.internal/v1/chat/completions"


@pytest.mark.asyncio
async def test_ollama_provider_success(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert "localhost:11434" in str(request.url)
        return httpx.Response(200, json={"message": {"content": "local answer"}})

    _patch_client(monkeypatch, handler)
    p = OllamaProvider()
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is True
    assert resp.text == "local answer"


@pytest.mark.asyncio
async def test_post_json_http_error_falls_back(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    _patch_client(monkeypatch, handler)
    p = AnthropicProvider(api_key="k")
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is False
    assert "refused" in resp.error


@pytest.mark.asyncio
async def test_post_json_non_200_falls_back(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server exploded")

    _patch_client(monkeypatch, handler)
    p = OpenAIProvider(api_key="k")
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is False
    assert "http 500" in resp.error


@pytest.mark.asyncio
async def test_post_json_malformed_response_falls_back(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        # Missing "choices" -> KeyError in _extract_openai.
        return httpx.Response(200, json={"unexpected": "shape"})

    _patch_client(monkeypatch, handler)
    p = OpenAIProvider(api_key="k")
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is False


@pytest.mark.asyncio
async def test_post_json_blank_completion_is_not_ok(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": "   "}})

    _patch_client(monkeypatch, handler)
    p = OllamaProvider()
    resp = await p.complete(system="s", prompt="p")
    assert resp.ok is False
    assert resp.text == ""


# -- get_provider --------------------------------------------------------


def test_get_provider_defaults_to_offline():
    settings = Settings(ai_provider="", secret_key="x")
    p = get_provider(settings)
    assert p.offline is True


def test_get_provider_unknown_name_falls_back_to_offline():
    settings = Settings(ai_provider="not-a-real-provider", secret_key="x")
    p = get_provider(settings)
    assert isinstance(p, OfflineProvider)


def test_get_provider_cloud_without_key_falls_back_to_offline():
    settings = Settings(ai_provider="anthropic", ai_api_key="", secret_key="x")
    p = get_provider(settings)
    assert isinstance(p, OfflineProvider)


def test_get_provider_cloud_with_key_is_live():
    settings = Settings(
        ai_provider="openai", ai_api_key="sk-real", ai_model="gpt-4o", secret_key="x"
    )
    p = get_provider(settings)
    assert isinstance(p, OpenAIProvider)
    assert p.offline is False
    assert p.model == "gpt-4o"


def test_get_provider_ollama_needs_no_key():
    settings = Settings(ai_provider="ollama", secret_key="x")
    p = get_provider(settings)
    assert isinstance(p, OllamaProvider)
    assert p.offline is False


def test_get_provider_uses_global_settings_by_default(monkeypatch):
    from pegase.core import config as cfg

    monkeypatch.setenv("PEGASE_AI_PROVIDER", "offline")
    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
    p = get_provider()
    assert p.offline is True

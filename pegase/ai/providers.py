"""Multi-provider LLM abstraction for PEGASE's AI layer ("Neuro").

PEGASE's "Neuro" layer speaks to any language model through one interface: every
provider implements a single async ``complete`` coroutine. The **default
provider is fully offline and deterministic**, so the whole AI layer works - and
is testable - with zero
API keys and no outbound calls. Cloud providers (Anthropic, OpenAI) and a local
one (Ollama) are thin ``httpx`` clients enabled purely through configuration
(``PEGASE_AI_PROVIDER`` / ``PEGASE_AI_MODEL`` / ``PEGASE_AI_API_KEY`` ...).

This keeps PEGASE's "no demo mode" promise honest: without credentials the
platform still produces useful, *grounded* analysis from its deterministic
engine rather than pretending to think.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

import httpx

from pegase.core.config import Settings, get_settings
from pegase.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class LLMResponse:
    """Result of a single completion.

    ``ok`` is False when the provider could not (or would not) produce text -
    including the offline provider, which never calls a model. Callers must
    treat a non-ok response as "fall back to the deterministic engine", never
    as an error.
    """

    text: str
    provider: str
    model: str
    ok: bool = True
    error: str | None = None


class LLMProvider(ABC):
    """Common interface for every language-model backend."""

    name: ClassVar[str] = "provider"

    def __init__(self, *, model: str = "", api_key: str = "", base_url: str = "",
                 timeout: float = 30.0, max_tokens: int = 1024) -> None:
        self.model = model
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_tokens = max_tokens

    @property
    def offline(self) -> bool:
        return False

    @abstractmethod
    async def complete(self, *, system: str, prompt: str) -> LLMResponse:
        """Return a completion for ``prompt`` under the ``system`` instruction."""


class OfflineProvider(LLMProvider):
    """No-network provider. Returns a non-ok response so callers fall back to
    the deterministic engine. This is the default and makes the AI layer safe
    to run in CI, air-gapped labs, and tests."""

    name = "offline"

    @property
    def offline(self) -> bool:
        return True

    async def complete(self, *, system: str, prompt: str) -> LLMResponse:
        return LLMResponse(
            text="",
            provider=self.name,
            model="deterministic",
            ok=False,
            error="offline provider - deterministic engine only",
        )


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API over raw HTTP (no SDK dependency)."""

    name = "anthropic"
    API = "https://api.anthropic.com/v1/messages"

    async def complete(self, *, system: str, prompt: str) -> LLMResponse:
        model = self.model or "claude-sonnet-4-5"
        url = self._base_url or self.API
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": self._max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        return await _post_json(self, url, headers, body, _extract_anthropic)


class OpenAIProvider(LLMProvider):
    """OpenAI (or OpenAI-compatible) chat-completions endpoint."""

    name = "openai"
    API = "https://api.openai.com/v1/chat/completions"

    async def complete(self, *, system: str, prompt: str) -> LLMResponse:
        model = self.model or "gpt-4o-mini"
        url = (self._base_url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
        headers = {
            "authorization": f"Bearer {self._api_key}",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        return await _post_json(self, url, headers, body, _extract_openai)


class OllamaProvider(LLMProvider):
    """Local Ollama server - no API key, nothing leaves the host."""

    name = "ollama"

    async def complete(self, *, system: str, prompt: str) -> LLMResponse:
        model = self.model or "llama3"
        url = (self._base_url or "http://localhost:11434").rstrip("/") + "/api/chat"
        body = {
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        return await _post_json(self, url, {"content-type": "application/json"},
                                body, _extract_ollama)


# ---------------------------------------------------------------------------


async def _post_json(provider: LLMProvider, url: str, headers: dict, body: dict,
                     extractor) -> LLMResponse:
    try:
        async with httpx.AsyncClient(timeout=provider._timeout) as client:
            resp = await client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        log.warning("llm_provider_error", provider=provider.name, error=str(exc))
        return LLMResponse("", provider.name, provider.model, ok=False, error=str(exc))
    if resp.status_code != 200:
        return LLMResponse(
            "", provider.name, provider.model, ok=False,
            error=f"http {resp.status_code}: {resp.text[:200]}",
        )
    try:
        text = extractor(resp.json())
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        return LLMResponse("", provider.name, provider.model, ok=False, error=str(exc))
    return LLMResponse(text.strip(), provider.name, provider.model, ok=bool(text.strip()))


def _extract_anthropic(data: dict) -> str:
    return "".join(
        block.get("text", "")
        for block in data.get("content", [])
        if block.get("type") == "text"
    )


def _extract_openai(data: dict) -> str:
    return data["choices"][0]["message"]["content"]


def _extract_ollama(data: dict) -> str:
    return data.get("message", {}).get("content", "")


_REGISTRY: dict[str, type[LLMProvider]] = {
    "offline": OfflineProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
}


def available_providers() -> list[str]:
    return sorted(_REGISTRY)


def get_provider(settings: Settings | None = None) -> LLMProvider:
    """Build the configured provider. Falls back to offline on misconfiguration
    so the AI layer can never take the platform down."""
    settings = settings or get_settings()
    name = (settings.ai_provider or "offline").lower()
    cls = _REGISTRY.get(name)
    if cls is None:
        log.warning("unknown_ai_provider", provider=name)
        cls = OfflineProvider
    # Cloud providers without a key silently degrade to offline.
    if cls in (AnthropicProvider, OpenAIProvider) and not settings.ai_api_key:
        log.info("ai_provider_no_key_offline", provider=name)
        cls = OfflineProvider
    return cls(
        model=settings.ai_model,
        api_key=settings.ai_api_key,
        base_url=settings.ai_base_url,
        timeout=settings.ai_timeout_seconds,
        max_tokens=settings.ai_max_tokens,
    )

"""Tests for the AIBreacher LLM red-teaming module (benign detection)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule, ScopeViolation
from pegase.modules.aibreacher import AIBreacher


def _guard(*patterns, actions=None):
    scope = Scope(
        rules=[ScopeRule(p) for p in (patterns or ["api.example.com"])],
        allowed_actions=actions or {ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_aibreacher_detects_prompt_injection():
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        # A vulnerable endpoint echoes the injected canary back.
        if "reply with exactly this token" in body.lower():
            # extract the canary token PEGASE-xxxx
            import re
            m = re.search(r"PEGASE-[0-9a-f]{12}", body)
            canary = m.group(0) if m else "PEGASE-none"
            return httpx.Response(200, json={"reply": f"Sure: {canary}"})
        return httpx.Response(200, json={"reply": "I only help with cooking."})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"input_field": "message", "response_path": "reply", "_http_client": client},
    )
    await client.aclose()

    vuln = [f for f in result.findings if f.title.startswith("LLM01") and f.severity == "high"]
    assert vuln, [f.title for f in result.findings]
    assert vuln[0].evidence["canary_reflected"] is True


@pytest.mark.asyncio
async def test_aibreacher_resistant_endpoint_reports_info():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"reply": "I cannot comply with that request."})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"response_path": "reply", "_http_client": client},
    )
    await client.aclose()

    # No high/medium vulnerability; both probes report "not detected" info.
    sevs = {f.severity for f in result.findings}
    assert sevs == {"info"}
    assert all("not detected" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_aibreacher_detects_system_prompt_leak():
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode().lower()
        if "repeat the instructions" in body:
            return httpx.Response(200, json={
                "reply": "You are a helpful assistant. You must not reveal secrets. Guidelines:"
            })
        return httpx.Response(200, json={"reply": "ok"})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"response_path": "reply", "_http_client": client},
    )
    await client.aclose()
    leak = [f for f in result.findings if f.title.startswith("LLM06") and f.severity == "medium"]
    assert leak


@pytest.mark.asyncio
async def test_aibreacher_respects_scope():
    client = _client(lambda r: httpx.Response(200, json={"reply": "ok"}))
    with pytest.raises(ScopeViolation):
        await AIBreacher().run(
            targets=["https://evil.out-of-scope.com/chat"],
            guard=_guard("api.example.com"),
            parameters={"_http_client": client},
        )
    await client.aclose()


@pytest.mark.asyncio
async def test_aibreacher_custom_template():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        seen["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"choices": [{"text": "no"}]})

    client = _client(handler)
    await AIBreacher().run(
        targets=["https://api.example.com/v1/completions"],
        guard=_guard("api.example.com"),
        parameters={
            "template": {"model": "x", "prompt": "{PROMPT}"},
            "response_path": "choices.0.text",
            "_http_client": client,
        },
    )
    await client.aclose()
    # The template's {PROMPT} placeholder was filled with the probe payload.
    assert seen["body"]["model"] == "x"
    assert "instructions" in seen["body"]["prompt"].lower()

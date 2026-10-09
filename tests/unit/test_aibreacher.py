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


@pytest.mark.asyncio
async def test_aibreacher_builds_own_client_when_not_injected(monkeypatch):
    """With no _http_client override, the module must build (and close) its
    own httpx.AsyncClient."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"reply": "no"})

    class _Patched(httpx.AsyncClient):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.aibreacher.httpx.AsyncClient", _Patched)

    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"response_path": "reply"},
    )
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_records_request_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"_http_client": client},
    )
    await client.aclose()
    assert result.findings == []
    errors = result.raw["errors"]
    assert len(errors) == 2
    assert "request-error" in errors[0]["detail"]


@pytest.mark.asyncio
async def test_aibreacher_records_http_error_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"_http_client": client},
    )
    await client.aclose()
    assert result.findings == []
    assert result.raw["errors"][0]["detail"] == "http 500"


@pytest.mark.asyncio
async def test_aibreacher_uses_get_method():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        return httpx.Response(200, json={"reply": "ok"})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"method": "GET", "response_path": "reply", "_http_client": client},
    )
    await client.aclose()
    assert seen["method"] == "GET"
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_malformed_json_falls_back_to_raw_text():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"not actually json", headers={"content-type": "application/json"}
        )

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"_http_client": client},
    )
    await client.aclose()
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_non_json_content_type_uses_plain_text():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"plain text reply", headers={"content-type": "text/plain"})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"_http_client": client},
    )
    await client.aclose()
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_response_path_list_index_and_out_of_range():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"text": "no"}]})

    client = _client(handler)
    # Index 5 doesn't exist -> the "" branch of the list-index traversal.
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"response_path": "choices.5", "_http_client": client},
    )
    await client.aclose()
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_response_path_through_non_traversable_value():
    def handler(request: httpx.Request) -> httpx.Response:
        # "choices" resolves to a plain string; the next path segment can
        # neither dict- nor list-index into it -> data = "".
        return httpx.Response(200, json={"choices": "not-a-list"})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"response_path": "choices.0", "_http_client": client},
    )
    await client.aclose()
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_no_response_path_stringifies_whole_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"a": 1, "b": 2})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"_http_client": client},  # no response_path
    )
    await client.aclose()
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_template_prompt_placeholder_inside_a_list():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"reply": "no"})

    client = _client(handler)
    await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={
            "template": {"messages": ["{PROMPT}"]},
            "response_path": "reply",
            "_http_client": client,
        },
    )
    await client.aclose()
    assert "instructions" in seen["body"]["messages"][0].lower()


@pytest.mark.asyncio
async def test_aibreacher_response_path_resolving_to_a_list_is_stringified():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"text": "a"}, {"text": "b"}]})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"response_path": "choices", "_http_client": client},
    )
    await client.aclose()
    assert len(result.findings) == 2


@pytest.mark.asyncio
async def test_aibreacher_response_path_resolving_to_a_number_is_stringified():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"count": 42})

    client = _client(handler)
    result = await AIBreacher().run(
        targets=["https://api.example.com/chat"],
        guard=_guard("api.example.com"),
        parameters={"response_path": "count", "_http_client": client},
    )
    await client.aclose()
    assert len(result.findings) == 2

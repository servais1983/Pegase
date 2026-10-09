"""WebBreacher tests using a httpx mock transport."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.webbreacher import WebBreacher


@pytest.mark.asyncio
async def test_webbreacher_flags_missing_headers_and_env(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/.env",):
            return httpx.Response(200, content=b"SECRET=top", headers={"content-type": "text/plain"})
        if request.url.path in ("/admin",):
            return httpx.Response(401)
        return httpx.Response(
            200,
            content=b"hello",
            headers={
                "Server": "nginx/1.10.0",
                "Content-Type": "text/html",
            },
        )

    transport = httpx.MockTransport(handler)

    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.webbreacher.httpx.AsyncClient", _Patched)

    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    result = await WebBreacher().run(targets=["http://example.com/"], guard=guard)

    titles = [f.title for f in result.findings]
    assert any("X-Frame-Options" in t for t in titles)
    assert any("Sensitive path exposed: /.env" in t for t in titles)
    assert any("Server fingerprint" in t for t in titles)


@pytest.mark.asyncio
async def test_webbreacher_records_http_request_failure(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.webbreacher.httpx.AsyncClient", _Patched)

    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    result = await WebBreacher().run(targets=["http://example.com/"], guard=guard)

    assert len(result.findings) == 1
    assert result.findings[0].title == "HTTP request failed"
    assert result.findings[0].severity == "info"


@pytest.mark.asyncio
async def test_webbreacher_present_security_header_is_not_flagged(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                content=b"hello",
                headers={"X-Frame-Options": "DENY", "Content-Type": "text/html"},
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.webbreacher.httpx.AsyncClient", _Patched)

    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    result = await WebBreacher().run(targets=["http://example.com/"], guard=guard)

    titles = [f.title for f in result.findings]
    assert not any("X-Frame-Options" in t for t in titles)
    # The other, still-missing headers are still flagged.
    assert any("Content-Security-Policy" in t for t in titles)


@pytest.mark.asyncio
async def test_webbreacher_sensitive_path_probe_request_error_is_skipped(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=b"hello", headers={"Content-Type": "text/html"})
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.webbreacher.httpx.AsyncClient", _Patched)

    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    result = await WebBreacher().run(targets=["http://example.com/"], guard=guard)

    # No "Sensitive path exposed" findings - every probe raised and was
    # skipped, but the module must not crash.
    assert not any("Sensitive path exposed" in f.title for f in result.findings)


def test_ensure_url_adds_https_scheme_to_bare_host():
    from pegase.modules.webbreacher import _ensure_url

    assert _ensure_url("example.com") == "https://example.com"
    assert _ensure_url("http://example.com") == "http://example.com"

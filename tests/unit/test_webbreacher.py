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

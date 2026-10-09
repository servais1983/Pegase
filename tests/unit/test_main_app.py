"""Tests for pegase.api.main: app factory, lifespan, exception handlers,
the dashboard's /graph page, and the pegase-api console-script entry point.
"""

from __future__ import annotations

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from pegase.core.scope import ActionType, ScopeViolation


def _fake_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/x",
        "headers": [],
        "query_string": b"",
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_lifespan_runs_startup_and_shutdown(tmp_path, monkeypatch):
    from pegase.api.main import create_app, lifespan

    monkeypatch.setenv("PEGASE_AUDIT_LOG_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PEGASE_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    from pegase.core import config as cfg

    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]

    app = create_app()
    async with lifespan(app):
        pass  # startup ran on __aenter__, shutdown will run on __aexit__
    assert (tmp_path / "audit.log").parent.exists()


@pytest.mark.asyncio
async def test_scope_violation_handler_shapes_response():
    from pegase.api.main import create_app

    app = create_app()
    handler = app.exception_handlers[ScopeViolation]
    exc = ScopeViolation("out of scope", target="evil.example.com", action=ActionType.ACTIVE)

    resp = await handler(_fake_request(), exc)
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 403
    body = resp.body.decode()
    assert "evil.example.com" in body
    assert "scope_violation" in body


@pytest.mark.asyncio
async def test_sqlalchemy_error_handler_returns_500():
    from pegase.api.main import create_app

    app = create_app()
    handler = app.exception_handlers[SQLAlchemyError]
    resp = await handler(_fake_request(), SQLAlchemyError("boom"))
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 500
    assert "database_error" in resp.body.decode()


@pytest.mark.asyncio
async def test_graph_page_renders(client):
    async with client as c:
        r = await c.get("/graph")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]


def test_run_entrypoint_calls_uvicorn(monkeypatch):
    import uvicorn

    captured: dict = {}

    def fake_run(target, **kw):
        captured["target"] = target
        captured.update(kw)

    monkeypatch.setattr(uvicorn, "run", fake_run)

    from pegase.api.main import run

    run()
    assert captured["target"] == "pegase.api.main:app"
    assert "host" in captured and "port" in captured

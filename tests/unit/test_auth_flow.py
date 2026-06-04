"""Refresh-token, logout and revocation flow tests."""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from pegase.api import main as api_main
from pegase.core.auth import hash_password
from pegase.db import session as db_session
from pegase.db.models import Base, User


@pytest.fixture()
def client(tmp_path, monkeypatch):
    url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(url, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with sm() as s:
            s.add(
                User(
                    username="admin",
                    email="a@example.org",
                    password_hash=hash_password("adminpass-strong-12345"),
                    role="admin",
                )
            )
            await s.commit()

    asyncio.run(_setup())
    monkeypatch.setattr(db_session, "_engine", engine)
    monkeypatch.setattr(db_session, "_sessionmaker", sm)
    os.environ["PEGASE_AUDIT_LOG_PATH"] = str(tmp_path / "audit.log")
    os.environ["PEGASE_ARTIFACT_DIR"] = str(tmp_path / "artifacts")
    from pegase.core import config as cfg

    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
    # Reset the revocation store so it's a fresh in-memory store per test.
    from pegase.core import revocation

    revocation._store = None
    app = api_main.create_app()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_login_returns_access_and_refresh(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["access_token"] and body["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_issues_new_access(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        refresh = r.json()["refresh_token"]
        r2 = await c.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r2.status_code == 200
        assert r2.json()["access_token"]


@pytest.mark.asyncio
async def test_access_token_cannot_be_used_as_refresh(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        access = r.json()["access_token"]
        r2 = await c.post("/api/v1/auth/refresh", json={"refresh_token": access})
        assert r2.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_token(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        access = r.json()["access_token"]
        h = {"Authorization": f"Bearer {access}"}
        assert (await c.get("/api/v1/auth/me", headers=h)).status_code == 200
        assert (await c.post("/api/v1/auth/logout", headers=h)).status_code == 204
        # Token is now revoked.
        assert (await c.get("/api/v1/auth/me", headers=h)).status_code == 401

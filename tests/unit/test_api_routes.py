"""API route smoke tests against an in-memory SQLite database."""

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
def sqlite_db(tmp_path, monkeypatch):
    """Swap the global sessionmaker for an in-memory SQLite one."""
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
                    email="admin@example.org",
                    password_hash=hash_password("adminpass-strong-12345"),
                    role="admin",
                )
            )
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_setup()) if False else None
    asyncio.run(_setup())

    monkeypatch.setattr(db_session, "_engine", engine)
    monkeypatch.setattr(db_session, "_sessionmaker", sm)
    yield sm
    asyncio.run(engine.dispose())


@pytest.fixture()
def client(sqlite_db, monkeypatch, tmp_path):
    os.environ["PEGASE_AUDIT_LOG_PATH"] = str(tmp_path / "audit.log")
    os.environ["PEGASE_ARTIFACT_DIR"] = str(tmp_path / "artifacts")
    # Disable slowapi during unit tests (no real redis).
    from pegase.core import config as cfg

    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]

    app = api_main.create_app()
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_unauthenticated_missions_rejected(client):
    async with client as c:
        r = await c.get("/api/v1/missions")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_full_mission_lifecycle(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}

        # /me
        r = await c.get("/api/v1/auth/me", headers=h)
        assert r.json()["username"] == "admin"

        # create draft (no authorization_token -> status=draft)
        r = await c.post(
            "/api/v1/missions",
            json={
                "name": "draft-1",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
            },
            headers=h,
        )
        assert r.status_code == 201
        assert r.json()["status"] == "draft"

        # create authorized
        r = await c.post(
            "/api/v1/missions",
            json={
                "name": "auth-1",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
                "authorization_token": "RoE-001",
            },
            headers=h,
        )
        assert r.status_code == 201
        mid = r.json()["id"]
        assert r.json()["status"] == "authorized"

        # list
        r = await c.get("/api/v1/missions", headers=h)
        assert len({m["id"] for m in r.json()}) >= 2

        # report on empty mission
        r = await c.get(f"/api/v1/reports/{mid}.json", headers=h)
        assert r.status_code == 200
        assert r.json()["summary"]["total"] == 0

        # bad module rejected on run
        r = await c.post(
            f"/api/v1/missions/{mid}/run",
            json={"modules": ["does-not-exist"]},
            headers=h,
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_run_without_authorization_is_rejected(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        token = r.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}
        r = await c.post(
            "/api/v1/missions",
            json={
                "name": "no-auth",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
            },
            headers=h,
        )
        mid = r.json()["id"]
        r = await c.post(
            f"/api/v1/missions/{mid}/run",
            json={"modules": ["recon"]},
            headers=h,
        )
        assert r.status_code == 409  # draft, not authorized


@pytest.mark.asyncio
async def test_system_endpoints(client):
    async with client as c:
        r = await c.get("/healthz")
        assert r.status_code == 200
        r = await c.get("/modules")
        assert r.status_code == 200
        names = {m["name"] for m in r.json()["modules"]}
        assert {"recon", "netassault", "webbreacher", "vulnmatrix", "socialmatrix"} <= names

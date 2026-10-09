"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("PEGASE_SECRET_KEY", "test-secret-not-for-production")
os.environ.setdefault("PEGASE_ENVIRONMENT", "development")


@pytest.fixture()
def tmp_audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


@pytest.fixture()
def sqlite_db(tmp_path, monkeypatch):
    """Swap the global sessionmaker for an in-memory SQLite one, seeded with
    a single admin user. Shared by every API-route test module."""
    from pegase.core.auth import hash_password
    from pegase.db import session as db_session
    from pegase.db.models import Base, User

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

    from pegase.api import main as api_main

    app = api_main.create_app()
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def admin_auth_headers(c: httpx.AsyncClient) -> dict[str, str]:
    """POST /auth/token as the seeded admin user and return a Bearer header."""
    r = await c.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "adminpass-strong-12345"},
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}

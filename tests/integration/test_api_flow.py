"""End-to-end API smoke test against a running Postgres."""

from __future__ import annotations

import httpx
import pytest

from pegase.api.main import create_app
from pegase.core.auth import hash_password
from pegase.db.models import Base, User
from pegase.db.session import get_engine, get_sessionmaker, reset_engine

pytestmark = pytest.mark.integration


@pytest.fixture()
async def admin_user():
    # Create the schema on the *same* engine the application uses so the
    # fixture works identically against Postgres and SQLite.
    await reset_engine()
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = get_sessionmaker()
    async with sm() as db:
        user = User(
            username="admin",
            email="admin@example.org",
            password_hash=hash_password("admin-password-12345"),
            role="admin",
        )
        db.add(user)
        await db.commit()
        yield user
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await reset_engine()


@pytest.fixture()
def app():
    return create_app()


@pytest.mark.asyncio
async def test_login_and_create_mission(app, admin_user):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        # auth
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "admin-password-12345"},
        )
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}

        # create mission
        r = await c.post(
            "/api/v1/missions",
            json={
                "name": "demo",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
                "allowed_actions": ["passive"],
                "authorization_token": "ROE-test-001",
            },
            headers=h,
        )
        assert r.status_code == 201, r.text
        mid = r.json()["id"]
        assert r.json()["status"] == "authorized"

        # list
        r = await c.get("/api/v1/missions", headers=h)
        assert r.status_code == 200
        assert any(m["id"] == mid for m in r.json())

        # report (no findings yet)
        r = await c.get(f"/api/v1/reports/{mid}.json", headers=h)
        assert r.status_code == 200
        assert r.json()["summary"]["total"] == 0

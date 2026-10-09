"""Remaining branch coverage for /api/v1/auth/* and pegase.api.deps.

Complements tests/unit/test_auth.py and test_auth_flow.py, which already
cover the happy paths. This file targets the error/edge branches: invalid
credentials, disabled users, malformed/garbage/revoked/foreign-user tokens,
role enforcement, and user creation.
"""

from __future__ import annotations

import pytest

from pegase.core.auth import create_access_token, create_refresh_token
from tests.conftest import admin_auth_headers


@pytest.mark.asyncio
async def test_token_rejects_unknown_username(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "nobody", "password": "whatever-12345"},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_token_rejects_wrong_password(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "totally-wrong-password"},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_token_rejects_disabled_user(client):
    from pegase.db import session as db_session
    from pegase.db.models import User

    async with client as c:
        async with db_session.get_sessionmaker()() as db:
            from pegase.core.auth import hash_password

            db.add(
                User(
                    username="disabled-guy",
                    email="disabled@example.org",
                    password_hash=hash_password("disabled-pass-12345"),
                    role="operator",
                    is_active=False,
                )
            )
            await db.commit()
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "disabled-guy", "password": "disabled-pass-12345"},
        )
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_me_rejects_garbage_token(client):
    async with client as c:
        r = await c.get(
            "/api/v1/auth/me", headers={"Authorization": "Bearer not-a-real-jwt"}
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_me_rejects_refresh_token_used_as_access(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        refresh = r.json()["refresh_token"]
        r2 = await c.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh}"}
        )
        assert r2.status_code == 401
        assert "refresh token" in r2.text
        assert h  # keep the admin header fixture call meaningful/used


@pytest.mark.asyncio
async def test_me_rejects_token_with_missing_subject(client):
    async with client as c:
        # extra overrides "sub" after it's set, producing a structurally
        # valid, correctly-signed token that simply carries no subject.
        tok = create_access_token("placeholder", role="admin", extra={"sub": ""})
        r = await c.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}
        )
        assert r.status_code == 401
        assert "missing subject" in r.text


@pytest.mark.asyncio
async def test_me_rejects_token_for_nonexistent_user(client):
    async with client as c:
        tok = create_access_token("no-such-user-id", role="admin")
        r = await c.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rejects_garbage_token(client):
    async with client as c:
        r = await c.post(
            "/api/v1/auth/refresh", json={"refresh_token": "not-a-real-jwt"}
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rejects_revoked_token(client):
    from pegase.core.auth import decode_token
    from pegase.core.revocation import get_revocation_store

    async with client as c:
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "adminpass-strong-12345"},
        )
        refresh = r.json()["refresh_token"]
        jti = decode_token(refresh)["jti"]
        get_revocation_store().revoke(jti, 3600)

        r2 = await c.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r2.status_code == 401
        assert "revoked" in r2.text


@pytest.mark.asyncio
async def test_refresh_rejects_token_for_nonexistent_user(client):
    async with client as c:
        tok = create_refresh_token("no-such-user-id", role="admin")
        r = await c.post("/api/v1/auth/refresh", json={"refresh_token": tok})
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_user_requires_admin_role(client):
    async with client as c:
        from pegase.core.auth import hash_password
        from pegase.db import session as db_session
        from pegase.db.models import User

        async with db_session.get_sessionmaker()() as db:
            db.add(
                User(
                    username="operator-1",
                    email="op1@example.org",
                    password_hash=hash_password("operator-pass-12345"),
                    role="operator",
                )
            )
            await db.commit()
        r = await c.post(
            "/api/v1/auth/token",
            data={"username": "operator-1", "password": "operator-pass-12345"},
        )
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        r2 = await c.post(
            "/api/v1/auth/users",
            json={
                "username": "new-user",
                "email": "new@example.org",
                "password": "new-pass-12345",
            },
            headers=h,
        )
        assert r2.status_code == 403


@pytest.mark.asyncio
async def test_create_user_succeeds_and_rejects_duplicate(client):
    async with client as c:
        h = await admin_auth_headers(c)
        payload = {
            "username": "brand-new",
            "email": "brand-new@example.org",
            "password": "brand-new-pass-12345",
            "role": "operator",
        }
        r = await c.post("/api/v1/auth/users", json=payload, headers=h)
        assert r.status_code == 201, r.text
        assert r.json()["username"] == "brand-new"

        r2 = await c.post("/api/v1/auth/users", json=payload, headers=h)
        assert r2.status_code == 409

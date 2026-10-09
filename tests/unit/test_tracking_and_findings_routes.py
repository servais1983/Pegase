"""Tests for the public /track endpoint and /api/v1/findings."""

from __future__ import annotations

import pytest

from tests.conftest import admin_auth_headers

# -- tracking (public, unauthenticated) -----------------------------------


@pytest.mark.asyncio
async def test_track_rejects_short_and_long_tokens(client):
    async with client as c:
        r = await c.get("/track/short")
        assert r.status_code == 404
        r = await c.get("/track/" + "x" * 129)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_track_records_click_once_and_is_idempotent(client):
    token = "a" * 32
    async with client as c:
        r = await c.get(f"/track/{token}?c=camp-1", headers={"User-Agent": "test-agent"})
        assert r.status_code == 200
        assert "phishing simulation" in r.text

        from sqlalchemy import select

        from pegase.db import session as db_session
        from pegase.db.models import PhishClick

        async with db_session.get_sessionmaker()() as db:
            rows = list(await db.scalars(select(PhishClick).where(PhishClick.token == token)))
            assert len(rows) == 1
            assert rows[0].campaign_id == "camp-1"
            assert rows[0].ip_hash is not None

        # A second hit on the same token must not create a duplicate row.
        r = await c.post(f"/track/{token}")
        assert r.status_code == 200
        async with db_session.get_sessionmaker()() as db:
            rows = list(await db.scalars(select(PhishClick).where(PhishClick.token == token)))
            assert len(rows) == 1


# -- findings ---------------------------------------------------------------


async def _create_mission_with_finding(c, h, **finding_kw) -> str:
    r = await c.post(
        "/api/v1/missions",
        json={
            "name": "findings-route-mission",
            "targets": ["scanme.nmap.org"],
            "scope_rules": [{"pattern": "scanme.nmap.org"}],
            "authorization_token": "RoE-findings-1",
        },
        headers=h,
    )
    mid = r.json()["id"]
    from pegase.db import session as db_session
    from pegase.db.models import Finding, Severity

    async with db_session.get_sessionmaker()() as db:
        db.add(
            Finding(
                mission_id=mid,
                module=finding_kw.get("module", "netassault"),
                target=finding_kw.get("target", "scanme.nmap.org"),
                title=finding_kw.get("title", "a finding"),
                description=finding_kw.get("description", ""),
                severity=Severity(finding_kw.get("severity", "info")),
                evidence={},
                references=[],
            )
        )
        await db.commit()
    return mid


@pytest.mark.asyncio
async def test_list_findings_requires_auth(client):
    async with client as c:
        r = await c.get("/api/v1/findings")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_list_findings_filters_by_mission_and_severity(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission_with_finding(c, h, title="high-one", severity="high")
        await _create_mission_with_finding(c, h, title="low-one", severity="low")

        r = await c.get(f"/api/v1/findings?mission_id={mid}", headers=h)
        assert r.status_code == 200, r.text
        titles = {f["title"] for f in r.json()}
        assert titles == {"high-one"}

        r = await c.get("/api/v1/findings?severity=low", headers=h)
        assert r.status_code == 200
        assert all(f["severity"] == "low" for f in r.json())

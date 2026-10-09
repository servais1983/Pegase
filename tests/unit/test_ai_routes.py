"""Tests for the /api/v1/ai/* routes (advisor, recommendation, jury)."""

from __future__ import annotations

import pytest

from tests.conftest import admin_auth_headers


async def _create_mission_with_findings(c, h, findings: list[dict]) -> str:
    r = await c.post(
        "/api/v1/missions",
        json={
            "name": "ai-routes-mission",
            "targets": ["scanme.nmap.org"],
            "scope_rules": [{"pattern": "scanme.nmap.org"}],
            "authorization_token": "RoE-ai-1",
        },
        headers=h,
    )
    mid = r.json()["id"]
    if findings:
        from pegase.db import session as db_session
        from pegase.db.models import Finding, Severity

        async with db_session.get_sessionmaker()() as db:
            for f in findings:
                db.add(
                    Finding(
                        mission_id=mid,
                        module=f.get("module", "netassault"),
                        target=f.get("target", "scanme.nmap.org"),
                        title=f["title"],
                        description=f.get("description", ""),
                        severity=Severity(f.get("severity", "info")),
                        evidence=f.get("evidence", {}),
                        references=f.get("references", []),
                    )
                )
            await db.commit()
    return mid


@pytest.mark.asyncio
async def test_ai_providers_endpoint(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/ai/providers", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "available" in body
        assert body["offline"] is True  # no API key configured in tests
        assert "jury_enabled" in body


@pytest.mark.asyncio
async def test_ai_providers_requires_auth(client):
    async with client as c:
        r = await c.get("/api/v1/ai/providers")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_ai_advise_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/ai/missions/does-not-exist/advise", headers=h)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_ai_advise_returns_grounded_analysis(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission_with_findings(
            c,
            h,
            [
                {
                    "title": "Open SSH service",
                    "description": "vsftpd 2.3.4",
                    "severity": "critical",
                    "evidence": {"product": "vsftpd", "version": "2.3.4"},
                }
            ],
        )
        r = await c.get(f"/api/v1/ai/missions/{mid}/advise", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["mission_id"] == mid
        assert "risk_score" in body["analysis"]
        assert 0 <= body["analysis"]["risk_score"] <= 100


@pytest.mark.asyncio
async def test_ai_recommend_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/ai/missions/does-not-exist/recommend", headers=h)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_ai_recommend_suggests_modules(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission_with_findings(
            c,
            h,
            [
                {
                    "module": "recon",
                    "title": "Open port 80/tcp (http)",
                    "description": "HTTP service observed",
                    "severity": "info",
                }
            ],
        )
        r = await c.get(f"/api/v1/ai/missions/{mid}/recommend", headers=h)
        assert r.status_code == 200, r.text
        recs = r.json()["recommendations"]
        assert any(rec["module"] == "webbreacher" for rec in recs)


@pytest.mark.asyncio
async def test_ai_jury_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/ai/missions/does-not-exist/jury", headers=h)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_ai_jury_skips_info_findings_and_adjudicates_the_rest(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission_with_findings(
            c,
            h,
            [
                {"title": "just info", "severity": "info"},
                {
                    "title": "critical with evidence",
                    "severity": "critical",
                    "evidence": {"product": "x", "version": "1"},
                    "references": ["https://example.com"],
                    "description": "well documented",
                },
            ],
        )
        r = await c.get(f"/api/v1/ai/missions/{mid}/jury", headers=h)
        assert r.status_code == 200, r.text
        verdicts = r.json()["verdicts"]
        # Only the non-info finding is adjudicated.
        assert len(verdicts) == 1
        assert verdicts[0]["finding"] == "critical with evidence"
        assert verdicts[0]["confirmed"] is True

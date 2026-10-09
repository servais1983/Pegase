"""Tests for the /api/v1/reports/* routes (JSON, HTML, attack graph)."""

from __future__ import annotations

import pytest

from tests.conftest import admin_auth_headers


async def _create_mission(c, h) -> str:
    r = await c.post(
        "/api/v1/missions",
        json={
            "name": "reports-mission",
            "targets": ["scanme.nmap.org"],
            "scope_rules": [{"pattern": "scanme.nmap.org"}],
            "authorization_token": "RoE-reports-1",
        },
        headers=h,
    )
    return r.json()["id"]


async def _add_finding(mid: str, **kw) -> None:
    from pegase.db import session as db_session
    from pegase.db.models import Finding, Severity

    async with db_session.get_sessionmaker()() as db:
        db.add(
            Finding(
                mission_id=mid,
                module=kw.get("module", "netassault"),
                target=kw.get("target", "scanme.nmap.org"),
                title=kw.get("title", "a finding"),
                description=kw.get("description", ""),
                severity=Severity(kw.get("severity", "info")),
                evidence=kw.get("evidence", {}),
                references=kw.get("references", []),
            )
        )
        await db.commit()


@pytest.mark.asyncio
async def test_json_report_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/reports/does-not-exist.json", headers=h)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_json_report_empty_mission(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission(c, h)
        r = await c.get(f"/api/v1/reports/{mid}.json", headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["summary"]["total"] == 0


@pytest.mark.asyncio
async def test_json_report_with_ai_flag(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission(c, h)
        await _add_finding(mid, title="Open SSH", severity="high")
        r = await c.get(f"/api/v1/reports/{mid}.json?ai=true", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["summary"]["total"] == 1
        # The grounded advisor section must be present and well-formed.
        assert "ai_analysis" in body
        assert 0 <= body["ai_analysis"]["risk_score"] <= 100


@pytest.mark.asyncio
async def test_html_report_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/reports/does-not-exist.html", headers=h)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_html_report_renders(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission(c, h)
        await _add_finding(mid, title="Open SSH", severity="high")
        r = await c.get(f"/api/v1/reports/{mid}.html", headers=h)
        assert r.status_code == 200, r.text
        assert "text/html" in r.headers["content-type"]
        assert "Open SSH" in r.text


@pytest.mark.asyncio
async def test_html_report_with_ai_flag(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission(c, h)
        await _add_finding(mid, title="Open SSH", severity="high")
        r = await c.get(f"/api/v1/reports/{mid}.html?ai=true", headers=h)
        assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_attack_graph_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/reports/does-not-exist/graph.json", headers=h)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_attack_graph_prefers_postxploit_evidence(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission(c, h)
        stored_graph = {"nodes": [{"id": "custom"}], "edges": [{"from": "a", "to": "b"}]}
        await _add_finding(
            mid,
            module="postxploit",
            title="Attack-path graph built",
            evidence={"graph": stored_graph},
        )
        r = await c.get(f"/api/v1/reports/{mid}/graph.json", headers=h)
        assert r.status_code == 200, r.text
        assert r.json() == stored_graph


@pytest.mark.asyncio
async def test_attack_graph_falls_back_to_synthesized_nodes(client):
    async with client as c:
        h = await admin_auth_headers(c)
        mid = await _create_mission(c, h)
        await _add_finding(
            mid, target="scanme.nmap.org", severity="medium", title="a"
        )
        await _add_finding(
            mid, target="scanme.nmap.org", severity="critical", title="b"
        )
        # A finding with an empty target must be skipped (no resolvable host).
        await _add_finding(mid, target="", severity="low", title="skip-me")

        r = await c.get(f"/api/v1/reports/{mid}/graph.json", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["edges"] == []
        node = next(n for n in body["nodes"] if n["id"] == "scanme.nmap.org")
        assert node["findings"] == 2
        assert node["max_severity"] == "critical"

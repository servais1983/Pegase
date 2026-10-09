"""Tests for the /api/v1/missions/* CRUD + run + autopilot routes."""

from __future__ import annotations

import pytest

from tests.conftest import admin_auth_headers


async def _create_mission(c, h, **overrides) -> dict:
    payload = {
        "name": "missions-route-test",
        "targets": ["scanme.nmap.org"],
        "scope_rules": [{"pattern": "scanme.nmap.org"}],
        "authorization_token": "RoE-missions-1",
    }
    payload.update(overrides)
    r = await c.post("/api/v1/missions", json=payload, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


# -- list ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_missions_filters_by_status(client):
    async with client as c:
        h = await admin_auth_headers(c)
        await _create_mission(c, h, name="draft-one", authorization_token=None)
        await _create_mission(c, h, name="authorized-one")

        r = await c.get("/api/v1/missions?status=draft", headers=h)
        assert r.status_code == 200, r.text
        names = {m["name"] for m in r.json()}
        assert "draft-one" in names
        assert "authorized-one" not in names


# -- get ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.get("/api/v1/missions/does-not-exist", headers=h)
        assert r.status_code == 404


# -- update ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.patch(
            "/api/v1/missions/does-not-exist", json={"name": "x"}, headers=h
        )
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_update_mission_rejected_while_running(client, monkeypatch):
    from pegase.tasks import scans as scans_mod

    monkeypatch.setattr(
        scans_mod.run_mission_task, "delay", lambda *a, **kw: type("T", (), {"id": "t"})()
    )
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(f"/api/v1/missions/{m['id']}/run", json={"modules": ["recon"]}, headers=h)
        assert r.status_code == 200, r.text

        r = await c.patch(
            f"/api/v1/missions/{m['id']}", json={"name": "renamed"}, headers=h
        )
        assert r.status_code == 409


@pytest.mark.asyncio
async def test_update_mission_sets_fields_and_authorizes_draft(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h, name="to-update", authorization_token=None)
        assert m["status"] == "draft"

        r = await c.patch(
            f"/api/v1/missions/{m['id']}",
            json={
                "client": "Acme",
                "scope_rules": [{"pattern": "scanme.nmap.org", "include": True}],
                "authorization_token": "RoE-now-authorized",
            },
            headers=h,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["client"] == "Acme"
        assert body["status"] == "authorized"


# -- delete ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.delete("/api/v1/missions/does-not-exist", headers=h)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_delete_mission_rejected_while_running(client, monkeypatch):
    from pegase.tasks import scans as scans_mod

    monkeypatch.setattr(
        scans_mod.run_mission_task, "delay", lambda *a, **kw: type("T", (), {"id": "t"})()
    )
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        await c.post(f"/api/v1/missions/{m['id']}/run", json={"modules": ["recon"]}, headers=h)
        r = await c.delete(f"/api/v1/missions/{m['id']}", headers=h)
        assert r.status_code == 409


@pytest.mark.asyncio
async def test_delete_mission_succeeds(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.delete(f"/api/v1/missions/{m['id']}", headers=h)
        assert r.status_code == 204
        r = await c.get(f"/api/v1/missions/{m['id']}", headers=h)
        assert r.status_code == 404


# -- run --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.post(
            "/api/v1/missions/does-not-exist/run", json={"modules": ["recon"]}, headers=h
        )
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_run_mission_rejects_no_targets(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h, targets=[])
        r = await c.post(
            f"/api/v1/missions/{m['id']}/run", json={"modules": ["recon"]}, headers=h
        )
        assert r.status_code == 400
        assert "no targets" in r.text


@pytest.mark.asyncio
async def test_run_mission_rejects_missing_authorization_token(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h, authorization_token=None)
        # Force-authorize without a token by patching the DB directly (the
        # API itself never allows this state, but run_mission must defend
        # against it independently).
        from pegase.db import session as db_session
        from pegase.db.models import Mission, MissionStatus

        async with db_session.get_sessionmaker()() as db:
            mission = await db.get(Mission, m["id"])
            mission.status = MissionStatus.AUTHORIZED
            await db.commit()

        r = await c.post(
            f"/api/v1/missions/{m['id']}/run", json={"modules": ["recon"]}, headers=h
        )
        assert r.status_code == 400
        assert "authorization token" in r.text


@pytest.mark.asyncio
async def test_run_mission_unknown_scenario_name(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(
            f"/api/v1/missions/{m['id']}/run",
            json={"scenario": "does-not-exist-scenario"},
            headers=h,
        )
        assert r.status_code == 400
        assert "unknown scenario" in r.text


@pytest.mark.asyncio
async def test_run_mission_scenario_validation_errors(client, tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(
        "name: bad\ndescription: x\nstages:\n  - name: s1\n    modules: [does-not-exist]\n",
        encoding="utf-8",
    )
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(
            f"/api/v1/missions/{m['id']}/run",
            json={"scenario": str(bad_yaml)},
            headers=h,
        )
        assert r.status_code == 400
        assert "unknown module" in r.text


@pytest.mark.asyncio
async def test_autopilot_run_with_scenario_merges_parameters(client, monkeypatch):
    from pegase.tasks import scans as scans_mod

    captured: dict = {}

    def fake_delay(mission_id, seed_modules, actor, **kw):
        captured["seed_modules"] = seed_modules
        return type("T", (), {"id": "task-ap-1"})()

    monkeypatch.setattr(scans_mod.run_autopilot_task, "delay", fake_delay)

    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(
            f"/api/v1/missions/{m['id']}/autopilot",
            json={"scenario": "external-apt"},
            headers=h,
        )
        assert r.status_code == 200, r.text
        assert captured["seed_modules"] == ["recon"]

        r = await c.get(f"/api/v1/missions/{m['id']}", headers=h)
        assert r.json()["parameters"]["netassault"]["ports"] == "1-1024"


@pytest.mark.asyncio
async def test_run_mission_rejects_unknown_module(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(
            f"/api/v1/missions/{m['id']}/run",
            json={"modules": ["does-not-exist"]},
            headers=h,
        )
        assert r.status_code == 400
        assert "unknown modules" in r.text


@pytest.mark.asyncio
async def test_run_mission_queues_and_merges_scenario_parameters(client, monkeypatch):
    from pegase.tasks import scans as scans_mod

    captured: dict = {}

    def fake_delay(mission_id, modules, actor):
        captured["mission_id"] = mission_id
        captured["modules"] = modules
        return type("T", (), {"id": "task-run-1"})()

    monkeypatch.setattr(scans_mod.run_mission_task, "delay", fake_delay)

    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(
            f"/api/v1/missions/{m['id']}/run",
            # external-apt carries a real per-module parameter (netassault
            # ports), exercising the merge loop rather than just module order.
            json={"scenario": "external-apt"},
            headers=h,
        )
        assert r.status_code == 200, r.text
        assert r.json()["task_id"] == "task-run-1"
        assert captured["modules"] == ["recon", "netassault", "webbreacher", "vulnmatrix", "postxploit"]

        r = await c.get(f"/api/v1/missions/{m['id']}", headers=h)
        assert r.json()["status"] == "running"
        assert r.json()["parameters"]["netassault"]["ports"] == "1-1024"


# -- autopilot ----------------------------------------------------------


@pytest.mark.asyncio
async def test_autopilot_run_mission_not_found(client):
    async with client as c:
        h = await admin_auth_headers(c)
        r = await c.post(
            "/api/v1/missions/does-not-exist/autopilot", json={}, headers=h
        )
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_autopilot_run_rejects_no_targets(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h, targets=[])
        r = await c.post(f"/api/v1/missions/{m['id']}/autopilot", json={}, headers=h)
        assert r.status_code == 400
        assert "no targets" in r.text


@pytest.mark.asyncio
async def test_autopilot_run_rejects_missing_authorization_token(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h, authorization_token=None)
        from pegase.db import session as db_session
        from pegase.db.models import Mission, MissionStatus

        async with db_session.get_sessionmaker()() as db:
            mission = await db.get(Mission, m["id"])
            mission.status = MissionStatus.AUTHORIZED
            await db.commit()

        r = await c.post(f"/api/v1/missions/{m['id']}/autopilot", json={}, headers=h)
        assert r.status_code == 400
        assert "authorization token" in r.text


@pytest.mark.asyncio
async def test_autopilot_run_unknown_scenario_name(client):
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(
            f"/api/v1/missions/{m['id']}/autopilot",
            json={"scenario": "does-not-exist-scenario"},
            headers=h,
        )
        assert r.status_code == 400
        assert "unknown scenario" in r.text


@pytest.mark.asyncio
async def test_autopilot_run_scenario_validation_errors(client, tmp_path):
    bad_yaml = tmp_path / "bad_ap.yaml"
    bad_yaml.write_text(
        "name: bad\ndescription: x\nstages:\n  - name: s1\n    modules: [does-not-exist]\n",
        encoding="utf-8",
    )
    async with client as c:
        h = await admin_auth_headers(c)
        m = await _create_mission(c, h)
        r = await c.post(
            f"/api/v1/missions/{m['id']}/autopilot",
            json={"scenario": str(bad_yaml)},
            headers=h,
        )
        assert r.status_code == 400
        assert "unknown module" in r.text

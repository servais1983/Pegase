"""API route smoke tests against an in-memory SQLite database."""

from __future__ import annotations

import pytest


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
async def test_autopilot_run_without_authorization_is_rejected(client):
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
                "name": "no-auth-autopilot",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
            },
            headers=h,
        )
        mid = r.json()["id"]
        r = await c.post(f"/api/v1/missions/{mid}/autopilot", json={}, headers=h)
        assert r.status_code == 409  # draft, not authorized


@pytest.mark.asyncio
async def test_autopilot_run_rejects_unknown_seed_module(client):
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
                "name": "autopilot-bad-seed",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
                "authorization_token": "RoE-ap-1",
            },
            headers=h,
        )
        mid = r.json()["id"]
        r = await c.post(
            f"/api/v1/missions/{mid}/autopilot",
            json={"seed_modules": ["does-not-exist"]},
            headers=h,
        )
        assert r.status_code == 400
        assert "unknown seed modules" in r.text


@pytest.mark.asyncio
async def test_autopilot_run_queues_task(client, monkeypatch):
    from pegase.tasks import scans as scans_mod

    class _FakeTask:
        id = "fake-task-id"

    captured: dict = {}

    def fake_delay(mission_id, seed_modules, actor, **kw):
        captured["mission_id"] = mission_id
        captured["seed_modules"] = seed_modules
        captured["actor"] = actor
        captured["kw"] = kw
        return _FakeTask()

    monkeypatch.setattr(scans_mod.run_autopilot_task, "delay", fake_delay)

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
                "name": "autopilot-ok",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
                "authorization_token": "RoE-ap-2",
            },
            headers=h,
        )
        mid = r.json()["id"]
        r = await c.post(
            f"/api/v1/missions/{mid}/autopilot",
            json={"seed_modules": ["recon"], "max_rounds": 3, "max_modules": 10},
            headers=h,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["mission_id"] == mid
        assert body["task_id"] == "fake-task-id"
        assert body["status"] == "queued"

        assert captured["mission_id"] == mid
        assert captured["seed_modules"] == ["recon"]
        assert captured["kw"] == {"max_rounds": 3, "max_modules": 10, "use_jury": False}

        # the mission flips to RUNNING synchronously, before the task result
        # (which this fake task never actually produces) would arrive.
        r = await c.get(f"/api/v1/missions/{mid}", headers=h)
        assert r.json()["status"] == "running"


@pytest.mark.asyncio
async def test_autopilot_run_with_scenario_seeds_from_first_stage(client, monkeypatch):
    from pegase.tasks import scans as scans_mod

    class _FakeTask:
        id = "fake-task-id-2"

    captured: dict = {}

    def fake_delay(mission_id, seed_modules, actor, **kw):
        captured["seed_modules"] = seed_modules
        return _FakeTask()

    monkeypatch.setattr(scans_mod.run_autopilot_task, "delay", fake_delay)

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
                "name": "autopilot-scenario",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
                "authorization_token": "RoE-ap-3",
            },
            headers=h,
        )
        mid = r.json()["id"]
        r = await c.post(
            f"/api/v1/missions/{mid}/autopilot",
            json={"scenario": "recon-and-enumerate"},
            headers=h,
        )
        assert r.status_code == 200, r.text
        assert captured["seed_modules"] == ["recon"]


@pytest.mark.asyncio
async def test_system_endpoints(client):
    async with client as c:
        r = await c.get("/healthz")
        assert r.status_code == 200
        r = await c.get("/modules")
        assert r.status_code == 200
        names = {m["name"] for m in r.json()["modules"]}
        assert {"recon", "netassault", "webbreacher", "vulnmatrix", "socialmatrix"} <= names


@pytest.mark.asyncio
async def test_dashboard_renders_without_any_missions(client):
    async with client as c:
        r = await c.get("/")
        assert r.status_code == 200
        assert "No missions yet" in r.text


@pytest.mark.asyncio
async def test_dashboard_renders_autopilot_watch_link_once_state_exists(
    client, sqlite_db
):
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
                "name": "dash-autopilot",
                "targets": ["scanme.nmap.org"],
                "scope_rules": [{"pattern": "scanme.nmap.org"}],
                "authorization_token": "RoE-dash-1",
            },
            headers=h,
        )
        mid = r.json()["id"]

        # Before any autopilot run: no "watch" link at all on the page.
        r = await c.get("/")
        assert "watch-autopilot" not in r.text

        # Simulate a completed AutoPilot run writing its summary, the way
        # run_autopilot_task does, without actually running the worker task.
        from pegase.db.models import Mission

        async with sqlite_db() as db:
            mission = await db.get(Mission, mid)
            mission.autopilot_state = {
                "rounds": [
                    {
                        "index": 1,
                        "modules_run": ["recon"],
                        "reasons": {"recon": "seed module"},
                        "new_findings": 1,
                        "errors": [],
                        "jury_verdicts": [],
                    }
                ],
                "stopped_reason": "no further module recommended",
            }
            await db.commit()

        r = await c.get("/")
        assert r.status_code == 200
        assert "watch-autopilot" in r.text
        assert "1 round(s)" in r.text
        assert f'data-mission-id="{mid}"' in r.text


@pytest.mark.asyncio
async def test_readyz_checks_db_connectivity(client):
    async with client as c:
        r = await c.get("/readyz")
        assert r.status_code == 200
        assert r.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(client):
    async with client as c:
        r = await c.get("/metrics")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]

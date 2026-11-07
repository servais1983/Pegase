"""Live full-stack test against the compose lab.

Opt-in: set PEGASE_E2E_BASE_URL (and the admin/redis variables below). The
default unit run skips this module so CI's Postgres service job is unchanged.

What is real when the variables are set:
  * HTTP through Nginx to the API (PEGASE_ENVIRONMENT=production)
  * JWT login, Postgres-backed missions and reports
  * a live Celery worker
  * WebBreacher HTTP GET against the compose service ``lab`` only
  * NetAssault nmap against that same hostname, port 80 only
  * Redis revocation of the access token (jti blocklist)

What this test deliberately does not do:
  * recon (crt.sh, public resolvers, WHOIS registries)
  * CloudStrike, S3 audit shipping, or a paid LLM provider
  * post-exploitation, exploit, wireless, physical, phishing, or toolforge
"""

from __future__ import annotations

import os
import time

import httpx
import pytest
import redis
from jose import jwt

pytestmark = pytest.mark.e2e

_LAB_HOST = "lab"
_ROE = "ROE-lab-local"


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"{name} is required when PEGASE_E2E_BASE_URL is set")
    return value


@pytest.fixture(scope="module")
def base_url() -> str:
    url = os.environ.get("PEGASE_E2E_BASE_URL", "").strip()
    if not url:
        pytest.skip("PEGASE_E2E_BASE_URL is unset; live stack test is opt-in")
    return url.rstrip("/")


def _wait_mission(client: httpx.Client, mission_id: str, headers: dict[str, str]) -> dict:
    deadline = time.time() + 180
    last = ""
    while time.time() < deadline:
        response = client.get(f"/api/v1/missions/{mission_id}", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        last = body.get("status", "")
        if last in {"completed", "failed"}:
            assert last == "completed", body
            return body
        time.sleep(2)
    pytest.fail(f"mission {mission_id} still {last!r} after 180s")


def _create_and_run(
    client: httpx.Client,
    headers: dict[str, str],
    *,
    name: str,
    targets: list[str],
    modules: list[str],
    parameters: dict,
) -> str:
    created = client.post(
        "/api/v1/missions",
        headers=headers,
        json={
            "name": name,
            "client": "lab",
            "targets": targets,
            "scope_rules": [{"pattern": _LAB_HOST, "include": True}],
            "allowed_actions": ["passive", "active"],
            "parameters": parameters,
            "authorization_token": _ROE,
        },
    )
    assert created.status_code == 201, created.text
    mission = created.json()
    assert mission["status"] == "authorized"
    assert mission["targets"] == targets
    assert mission["scope_rules"] == [{"pattern": _LAB_HOST, "include": True}]

    queued = client.post(
        f"/api/v1/missions/{mission['id']}/run",
        headers=headers,
        json={"modules": modules},
    )
    assert queued.status_code == 200, queued.text
    assert queued.json()["task_id"]
    _wait_mission(client, mission["id"], headers)
    return mission["id"]


def test_live_stack_mission_report_and_redis_revocation(base_url: str) -> None:
    username = _required("PEGASE_E2E_USERNAME")
    password = _required("PEGASE_E2E_PASSWORD")
    redis_url = _required("PEGASE_E2E_REDIS_URL")

    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        health = client.get("/healthz")
        assert health.status_code == 200, health.text
        assert health.json()["status"] == "ok"
        ready = client.get("/readyz")
        assert ready.status_code == 200, ready.text

        login = client.post(
            "/api/v1/auth/token",
            data={"username": username, "password": password},
        )
        assert login.status_code == 200, login.text
        token = login.json()["access_token"]
        assert login.json()["refresh_token"]
        headers = {"Authorization": f"Bearer {token}"}

        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200, me.text
        assert me.json()["username"] == username

        web_id = _create_and_run(
            client,
            headers,
            name="lab-http",
            targets=[f"http://{_LAB_HOST}"],
            modules=["webbreacher"],
            parameters={"webbreacher": {"timeout": 10}},
        )
        web_report = client.get(f"/api/v1/reports/{web_id}.json", headers=headers)
        assert web_report.status_code == 200, web_report.text
        web_body = web_report.json()
        assert web_body["mission"]["id"] == web_id
        assert web_body["mission"]["targets"] == [f"http://{_LAB_HOST}"]
        assert web_body["summary"]["total"] >= 1
        web_findings = web_body["findings"]
        assert all(item["module"] == "webbreacher" for item in web_findings)
        assert any(_LAB_HOST in item["target"] for item in web_findings)
        assert any(item["evidence"] for item in web_findings)

        nmap_id = _create_and_run(
            client,
            headers,
            name="lab-nmap",
            targets=[_LAB_HOST],
            modules=["netassault"],
            parameters={"netassault": {"ports": "80", "timing": 3}},
        )
        nmap_report = client.get(f"/api/v1/reports/{nmap_id}.json", headers=headers)
        assert nmap_report.status_code == 200, nmap_report.text
        nmap_findings = nmap_report.json()["findings"]
        assert nmap_report.json()["summary"]["total"] >= 1
        assert any(
            item["module"] == "netassault" and "80" in item["title"]
            for item in nmap_findings
        )

        logout = client.post("/api/v1/auth/logout", headers=headers)
        assert logout.status_code == 204, logout.text

    claims = jwt.get_unverified_claims(token)
    jti = claims["jti"]
    store = redis.Redis.from_url(redis_url, decode_responses=True)
    try:
        assert store.get(f"pegase:revoked:{jti}") == "1"
    finally:
        store.close()

    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        rejected = client.get("/api/v1/auth/me", headers=headers)
        assert rejected.status_code == 401, rejected.text
        assert "revoked" in rejected.text

        again = client.post(
            "/api/v1/auth/token",
            data={"username": username, "password": password},
        )
        assert again.status_code == 200, again.text
        fresh = {"Authorization": f"Bearer {again.json()['access_token']}"}
        assert client.get("/api/v1/auth/me", headers=fresh).status_code == 200

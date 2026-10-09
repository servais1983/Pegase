"""VulnMatrix correlation tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.vulnmatrix import VulnMatrix


@pytest.mark.asyncio
async def test_vulnmatrix_matches_vsftpd_backdoor():
    scope = Scope(
        rules=[ScopeRule("10.0.0.0/24")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    prior = [
        {
            "target": "10.0.0.5",
            "title": "Open port 21/tcp (ftp)",
            "description": "vsftpd 2.3.4",
            "evidence": {"product": "vsftpd", "version": "2.3.4"},
        }
    ]
    result = await VulnMatrix().run(
        targets=[], guard=guard, parameters={"findings": prior}
    )
    assert any(f.severity == "critical" for f in result.findings)


def _guard(pattern: str = "10.0.0.0/24") -> ScopeGuard:
    scope = Scope(
        rules=[ScopeRule(pattern)],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


@pytest.mark.asyncio
async def test_vulnmatrix_no_match_for_modern_versions():
    prior = [
        {
            "target": "10.0.0.5",
            "title": "Open port 22/tcp (ssh)",
            "description": "OpenSSH 9.6",
            "evidence": {"product": "OpenSSH", "version": "9.6"},
        }
    ]
    result = await VulnMatrix().run(
        targets=[], guard=_guard(), parameters={"findings": prior}
    )
    assert result.findings == []


@pytest.mark.asyncio
async def test_vulnmatrix_skips_out_of_scope_target():
    prior = [
        {
            "target": "203.0.113.9",  # outside the 10.0.0.0/24 scope
            "title": "vsftpd 2.3.4",
            "description": "vsftpd 2.3.4",
            "evidence": {"product": "vsftpd", "version": "2.3.4"},
        }
    ]
    result = await VulnMatrix().run(
        targets=[], guard=_guard(), parameters={"findings": prior}
    )
    assert result.findings == []


@pytest.mark.asyncio
async def test_vulnmatrix_nvd_lookup_adds_cve_findings(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("apiKey") == "fake-key"
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-99999",
                        "descriptions": [{"lang": "en", "value": "demo vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ]
        }
        return httpx.Response(200, content=json.dumps(payload).encode())

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.vulnmatrix.httpx.AsyncClient", _Patched)

    prior = [
        {
            "target": "10.0.0.7",
            "title": "unrelated banner",
            "description": "",
            "evidence": {"product": "acme-widget", "version": "1.0"},
        }
    ]
    result = await VulnMatrix().run(
        targets=[],
        guard=_guard(),
        parameters={"findings": prior, "nvd_api_key": "fake-key"},
    )
    assert any(f.title == "CVE-2024-99999" and f.severity == "critical" for f in result.findings)


@pytest.mark.asyncio
async def test_vulnmatrix_nvd_http_error_yields_no_cve_findings(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.vulnmatrix.httpx.AsyncClient", _Patched)

    prior = [
        {"target": "10.0.0.7", "title": "x", "description": "",
         "evidence": {"product": "acme", "version": "1.0"}}
    ]
    result = await VulnMatrix().run(
        targets=[], guard=_guard(), parameters={"findings": prior, "nvd_api_key": "k"}
    )
    assert result.findings == []


@pytest.mark.asyncio
async def test_vulnmatrix_nvd_non_200_yields_no_cve_findings(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.vulnmatrix.httpx.AsyncClient", _Patched)

    prior = [
        {"target": "10.0.0.7", "title": "x", "description": "",
         "evidence": {"product": "acme", "version": "1.0"}}
    ]
    result = await VulnMatrix().run(
        targets=[], guard=_guard(), parameters={"findings": prior, "nvd_api_key": "k"}
    )
    assert result.findings == []


@pytest.mark.asyncio
async def test_vulnmatrix_nvd_severity_bands(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        payload = {
            "vulnerabilities": [
                {"cve": {"id": f"CVE-SEV-{score}", "descriptions": [{"lang": "en", "value": "d"}],
                          "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}}}
                for score in (8.5, 5.0, 2.0)
            ]
        }
        return httpx.Response(200, content=json.dumps(payload).encode())

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.vulnmatrix.httpx.AsyncClient", _Patched)

    prior = [
        {"target": "10.0.0.7", "title": "x", "description": "",
         "evidence": {"product": "acme", "version": "1.0"}}
    ]
    result = await VulnMatrix().run(
        targets=[], guard=_guard(), parameters={"findings": prior, "nvd_api_key": "k"}
    )
    sev_by_id = {f.title: f.severity for f in result.findings}
    assert sev_by_id["CVE-SEV-8.5"] == "high"
    assert sev_by_id["CVE-SEV-5.0"] == "medium"
    assert sev_by_id["CVE-SEV-2.0"] == "low"

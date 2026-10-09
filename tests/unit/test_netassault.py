"""NetAssault tests — the nmap binary/scan is mocked, no real scanning."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule, ScopeViolation
from pegase.modules.netassault import NetAssault


def _guard(pattern: str = "10.0.0.0/24") -> ScopeGuard:
    scope = Scope(
        rules=[ScopeRule(pattern)],
        allowed_actions={ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


_FAKE_SCAN = {
    "scan": {
        "10.0.0.5": {
            "tcp": {
                22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9"},
                6379: {"state": "open", "name": "redis", "product": "", "version": ""},
                80: {"state": "closed", "name": "http", "product": "", "version": ""},
            }
        }
    }
}


@pytest.mark.asyncio
async def test_netassault_reports_open_ports_with_severity(monkeypatch):
    monkeypatch.setattr("pegase.modules.netassault.shutil.which", lambda _b: "/usr/bin/nmap")
    monkeypatch.setattr(
        "pegase.modules.netassault._run_nmap",
        lambda target, ports, arguments: _FAKE_SCAN,
    )

    result = await NetAssault().run(targets=["10.0.0.5"], guard=_guard())

    # 22 isn't in _SEVERITY_BY_PORT -> "info"; 6379 (redis) -> "high"; 80 closed -> skipped
    assert any(f.title.startswith("Open port 22/tcp") and f.severity == "info" for f in result.findings)
    assert any(f.title.startswith("Open port 6379/tcp") and f.severity == "high" for f in result.findings)
    assert not any("80/tcp" in f.title for f in result.findings)
    assert "OpenSSH 8.9" in next(f.description for f in result.findings if "22/tcp" in f.title)


@pytest.mark.asyncio
async def test_netassault_no_open_ports_yields_no_findings(monkeypatch):
    monkeypatch.setattr("pegase.modules.netassault.shutil.which", lambda _b: "/usr/bin/nmap")
    monkeypatch.setattr(
        "pegase.modules.netassault._run_nmap",
        lambda target, ports, arguments: {"scan": {"10.0.0.9": {"tcp": {}}}},
    )

    result = await NetAssault().run(targets=["10.0.0.9"], guard=_guard())
    assert result.findings == []


@pytest.mark.asyncio
async def test_netassault_raises_when_nmap_missing(monkeypatch):
    monkeypatch.setattr("pegase.modules.netassault.shutil.which", lambda _b: None)
    with pytest.raises(RuntimeError, match="nmap binary not found"):
        await NetAssault().run(targets=["10.0.0.5"], guard=_guard())


@pytest.mark.asyncio
async def test_netassault_enforces_scope_guard(monkeypatch):
    monkeypatch.setattr("pegase.modules.netassault.shutil.which", lambda _b: "/usr/bin/nmap")
    monkeypatch.setattr(
        "pegase.modules.netassault._run_nmap",
        lambda target, ports, arguments: _FAKE_SCAN,
    )
    with pytest.raises(ScopeViolation):
        await NetAssault().run(
            targets=["203.0.113.9"], guard=_guard("10.0.0.0/24")
        )


@pytest.mark.asyncio
async def test_netassault_passes_custom_parameters(monkeypatch):
    monkeypatch.setattr("pegase.modules.netassault.shutil.which", lambda _b: "/usr/bin/nmap")
    captured = {}

    def fake_run(target, ports, arguments):
        captured["target"] = target
        captured["ports"] = ports
        captured["arguments"] = arguments
        return {"scan": {}}

    monkeypatch.setattr("pegase.modules.netassault._run_nmap", fake_run)

    await NetAssault().run(
        targets=["10.0.0.5"],
        guard=_guard(),
        parameters={"ports": "80,443", "timing": 5, "arguments": "--open"},
    )
    assert captured["ports"] == "80,443"
    assert "-T5" in captured["arguments"]
    assert "--open" in captured["arguments"]

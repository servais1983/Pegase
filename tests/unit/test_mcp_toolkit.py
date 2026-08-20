"""Tests for the governed MCP toolkit.

These exercise the governance guarantees an autonomous agent relies on:
Rules-of-Engagement gating, least-privilege defaults, scope re-validation, and
the tamper-evident audit trail — all without touching the network (a fake
module stands in for the real ones).
"""

from __future__ import annotations

import json

import pytest

from pegase.core.audit import AuditLog
from pegase.core.scope import ActionType, ScopeGuard
from pegase.mcp import toolkit
from pegase.modules.base import Finding, ModuleResult


class _FakePassive:
    name = "fakepassive"
    description = "deterministic passive fake"
    action_type = ActionType.PASSIVE
    needs_upstream_findings = False

    async def run(self, *, targets, guard: ScopeGuard, parameters=None) -> ModuleResult:
        findings = []
        for t in targets:
            guard.check(t, ActionType.PASSIVE)  # scope guard re-validates
            findings.append(
                Finding(
                    module=self.name,
                    target=t,
                    title="Observed",
                    description="deterministic finding",
                    severity="high",
                )
            )
        return ModuleResult(module=self.name, findings=findings)


class _FakeActive(_FakePassive):
    name = "fakeactive"
    action_type = ActionType.ACTIVE

    async def run(self, *, targets, guard: ScopeGuard, parameters=None) -> ModuleResult:
        for t in targets:
            guard.check(t, ActionType.ACTIVE)  # requires allow_active
        return ModuleResult(module=self.name, findings=[])


@pytest.fixture()
def audit(tmp_audit_path) -> AuditLog:
    return AuditLog(tmp_audit_path)


@pytest.fixture()
def fake_registry(monkeypatch):
    registry = {_FakePassive.name: _FakePassive, _FakeActive.name: _FakeActive}
    monkeypatch.setattr(toolkit, "available_modules", lambda: registry)
    return registry


def _actions(audit: AuditLog) -> list[str]:
    return [json.loads(line)["action"] for line in audit.path.read_text().splitlines() if line]


def test_scan_without_authorization_is_denied_and_audited(audit, fake_registry):
    result = toolkit.run_scan(
        targets=["app.example.com"], modules=["fakepassive"], audit=audit
    )
    assert result["status"] == "denied"
    actions = _actions(audit)
    # The agent's request is recorded, then the RoE denial — module never ran.
    assert "mcp.tool.invoked" in actions
    assert "mcp.denied" in actions
    assert "module.started" not in actions


def test_authorized_passive_scan_runs_and_chain_verifies(audit, fake_registry):
    result = toolkit.run_scan(
        targets=["app.example.com"],
        modules=["fakepassive"],
        authorization="ROE-1",
        audit=audit,
    )
    assert result["status"] == "ok"
    assert result["summary"]["total"] == 1
    assert result["summary"]["by_severity"] == {"high": 1}
    assert result["allowed_actions"] == ["passive"]
    assert result["audit"]["verified"] is True
    assert "mcp.tool.invoked" in _actions(audit)


def test_active_module_needs_explicit_allow_active(audit, fake_registry):
    # Passive-only default: the active module's guard.check raises -> recorded
    # as a module error and a scope denial, not a crash.
    denied = toolkit.run_scan(
        targets=["app.example.com"],
        modules=["fakeactive"],
        authorization="ROE-1",
        audit=audit,
    )
    assert denied["status"] == "ok"
    assert denied["errors"], "active module should be denied under passive default"
    assert "scope.denied" in _actions(audit)

    # Opt in to active and it is allowed.
    allowed = toolkit.run_scan(
        targets=["app.example.com"],
        modules=["fakeactive"],
        authorization="ROE-1",
        allow_active=True,
        audit=audit,
    )
    assert allowed["status"] == "ok"
    assert allowed["errors"] == []
    assert "active" in allowed["allowed_actions"]


def test_target_outside_scope_is_denied_even_if_agent_supplies_it(audit, fake_registry):
    # The agent asks to scan a target that the scope patterns do not cover.
    result = toolkit.run_scan(
        targets=["evil.example.org"],
        modules=["fakepassive"],
        authorization="ROE-1",
        scope_patterns=["*.example.com"],
        audit=audit,
    )
    assert result["status"] == "ok"
    assert result["summary"]["total"] == 0
    assert result["errors"], "out-of-scope target must be refused by the guard"
    assert "scope.denied" in _actions(audit)


def test_unknown_module_is_rejected(audit, fake_registry):
    result = toolkit.run_scan(
        targets=["app.example.com"],
        modules=["does-not-exist"],
        authorization="ROE-1",
        audit=audit,
    )
    assert result["status"] == "error"
    assert "unknown modules" in result["reason"]
    assert "mcp.rejected" in _actions(audit)


def test_scan_can_emit_sarif_report(audit, fake_registry):
    result = toolkit.run_scan(
        targets=["app.example.com"],
        modules=["fakepassive"],
        authorization="ROE-1",
        report_format="sarif",
        audit=audit,
    )
    assert result["report_format"] == "sarif"
    sarif = json.loads(result["report"])
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "PEGASE"


def test_run_scenario_rejects_unknown_scenario(audit, fake_registry):
    result = toolkit.run_scenario(
        targets=["app.example.com"],
        scenario="no-such-scenario",
        authorization="ROE-1",
        audit=audit,
    )
    assert result["status"] == "error"


def test_verify_audit_reports_intact_chain(audit, fake_registry):
    toolkit.run_scan(
        targets=["app.example.com"],
        modules=["fakepassive"],
        authorization="ROE-1",
        audit=audit,
    )
    report = toolkit.verify_audit(audit=audit)
    assert report["status"] == "ok"
    assert report["verified"] is True
    assert report["error"] is None
    assert report["entries"] == len(_actions(audit))


def test_list_tools_are_read_only_and_complete():
    modules = toolkit.list_modules()["modules"]
    names = {m["name"] for m in modules}
    assert {"recon", "webbreacher", "vulnmatrix"} <= names
    scenarios = {s["name"] for s in toolkit.list_scenarios()["scenarios"]}
    assert "recon-and-enumerate" in scenarios

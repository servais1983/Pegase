"""AutoPilot tests.

Uses a small fake module registry (monkeypatched into both
``pegase.core.autopilot`` and ``pegase.ai.selection``) so the test exercises
the real round-chaining/stopping/audit logic and the real evidence-pattern
planner, without depending on recon/webbreacher's real network behaviour.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.audit import AuditLog
from pegase.core.autopilot import AutoPilot
from pegase.core.orchestrator import MissionContext
from pegase.core.scope import ActionType, Scope, ScopeRule
from pegase.modules.base import Finding, Module, ModuleResult


class _FakeRecon(Module):
    name = "recon"
    action_type = ActionType.PASSIVE

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        guard.check(targets[0], self.action_type)
        return ModuleResult(
            module=self.name,
            findings=[
                Finding(
                    module=self.name,
                    target=targets[0],
                    title="Open port 80/tcp (http)",
                    description="HTTP service observed on example.com",
                )
            ],
        )


class _FakeWebBreacher(Module):
    name = "webbreacher"
    action_type = ActionType.ACTIVE

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        guard.check(targets[0], self.action_type)
        return ModuleResult(
            module=self.name,
            findings=[
                Finding(
                    module=self.name,
                    target=targets[0],
                    title="Missing security header",
                    description="No CSP header set",
                )
            ],
        )


class _FakeVulnMatrix(Module):
    name = "vulnmatrix"
    action_type = ActionType.PASSIVE
    needs_upstream_findings = True

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        return ModuleResult(module=self.name)


class _FakePostXploit(Module):
    name = "postxploit"
    action_type = ActionType.PASSIVE
    needs_upstream_findings = True

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        return ModuleResult(module=self.name)


class _FakeMobileHunter(Module):
    name = "mobilehunter"
    action_type = ActionType.PASSIVE
    autopilot_ready = False

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        raise AssertionError("mobilehunter is not autopilot-ready and must never run here")


_REGISTRY = {
    c.name: c
    for c in (_FakeRecon, _FakeWebBreacher, _FakeVulnMatrix, _FakePostXploit, _FakeMobileHunter)
}


def _patch_registry(monkeypatch):
    monkeypatch.setattr("pegase.core.autopilot.available_modules", lambda: _REGISTRY)
    monkeypatch.setattr("pegase.ai.selection.available_modules", lambda: _REGISTRY)


def _ctx(actions: set[ActionType]) -> MissionContext:
    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions=actions,
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return MissionContext(
        mission_id="auto-1",
        actor="tester",
        scope=scope,
        targets=["example.com"],
        parameters={},
    )


@pytest.mark.asyncio
async def test_autopilot_chains_recon_into_recommended_modules(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch)
    audit = AuditLog(tmp_audit_path)
    ctx = _ctx({ActionType.PASSIVE, ActionType.ACTIVE})

    autopilot = AutoPilot(audit=audit, max_rounds=5, max_modules=10)
    outcome = await autopilot.run(ctx)

    modules_run = {m for r in outcome.rounds for m in r.modules_run}
    assert modules_run == {"recon", "webbreacher", "vulnmatrix", "postxploit"}
    assert "mobilehunter" not in modules_run
    assert outcome.stopped_reason == "no further module recommended"
    assert len(outcome.findings) >= 2
    assert outcome.errors == []


@pytest.mark.asyncio
async def test_autopilot_respects_max_modules_budget(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch)
    audit = AuditLog(tmp_audit_path)
    ctx = _ctx({ActionType.PASSIVE, ActionType.ACTIVE})

    autopilot = AutoPilot(audit=audit, max_rounds=5, max_modules=1)
    outcome = await autopilot.run(ctx)

    modules_run = {m for r in outcome.rounds for m in r.modules_run}
    assert modules_run == {"recon"}
    assert outcome.stopped_reason == "max_modules budget exhausted"


@pytest.mark.asyncio
async def test_autopilot_respects_max_rounds(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch)
    audit = AuditLog(tmp_audit_path)
    ctx = _ctx({ActionType.PASSIVE, ActionType.ACTIVE})

    autopilot = AutoPilot(audit=audit, max_rounds=1, max_modules=10)
    outcome = await autopilot.run(ctx)

    assert len(outcome.rounds) == 1
    assert outcome.stopped_reason == "max_rounds reached"


@pytest.mark.asyncio
async def test_autopilot_respects_scope_action_restrictions(tmp_audit_path, monkeypatch):
    """Only PASSIVE is allowed, so the ACTIVE webbreacher must never run,
    even though the recon finding's signal would otherwise trigger it."""
    _patch_registry(monkeypatch)
    audit = AuditLog(tmp_audit_path)
    ctx = _ctx({ActionType.PASSIVE})

    autopilot = AutoPilot(audit=audit, max_rounds=5, max_modules=10)
    outcome = await autopilot.run(ctx)

    modules_run = {m for r in outcome.rounds for m in r.modules_run}
    assert "webbreacher" not in modules_run
    assert modules_run == {"recon", "vulnmatrix", "postxploit"}


@pytest.mark.asyncio
async def test_autopilot_never_selects_non_autopilot_ready_modules(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch)
    audit = AuditLog(tmp_audit_path)
    autopilot = AutoPilot(audit=audit)
    ctx = _ctx({ActionType.PASSIVE, ActionType.ACTIVE})

    findings = [
        Finding(
            module="recon",
            target="example.com",
            title="Android apk artifact found",
            description="An exposed android apk download link was observed",
        )
    ]
    recs = autopilot._next_recommendations(  # noqa: SLF001 - testing the gate directly
        findings, ctx, _REGISTRY, ctx.scope.allowed_actions, set()
    )
    assert all(r.module != "mobilehunter" for r in recs)


@pytest.mark.asyncio
async def test_autopilot_requires_a_valid_seed_module(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch)
    audit = AuditLog(tmp_audit_path)
    ctx = _ctx({ActionType.PASSIVE})
    autopilot = AutoPilot(audit=audit, seed_modules=("nonexistent",))
    with pytest.raises(ValueError, match="no valid seed modules"):
        await autopilot.run(ctx)


@pytest.mark.asyncio
async def test_autopilot_rejects_invalid_bounds():
    with pytest.raises(ValueError, match="max_rounds"):
        AutoPilot(max_rounds=0)
    with pytest.raises(ValueError, match="max_modules"):
        AutoPilot(max_modules=0)


@pytest.mark.asyncio
async def test_autopilot_audit_trail_is_complete_and_tamper_evident(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch)
    audit = AuditLog(tmp_audit_path)
    ctx = _ctx({ActionType.PASSIVE, ActionType.ACTIVE})
    autopilot = AutoPilot(audit=audit, max_rounds=5, max_modules=10)
    await autopilot.run(ctx)

    ok, _count, error = audit.verify()
    assert ok, error

    text = tmp_audit_path.read_text(encoding="utf-8")
    assert '"autopilot.started"' in text
    assert '"autopilot.round_finished"' in text
    assert '"autopilot.plan"' in text
    assert '"autopilot.finished"' in text


def test_autopilot_outcome_to_dict_round_trips_json():
    import json

    from pegase.core.autopilot import AutoPilotOutcome, AutoPilotRound

    outcome = AutoPilotOutcome(
        mission_id="m",
        rounds=[AutoPilotRound(index=1, modules_run=["recon"], reasons={"recon": "seed"}, new_findings=1)],
        findings=[
            Finding(module="recon", target="x", title="t", description="d", severity="info")
        ],
        module_results=[],
        errors=[],
        stopped_reason="max_rounds reached",
    )
    json.dumps(outcome.to_dict())  # must not raise

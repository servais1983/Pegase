"""Jury-gated AutoPilot chaining.

A finding must clear the (deterministic, offline) jury's confidence bar
before it is allowed to influence what AutoPilot runs next. A low-confidence
finding still shows up in the final report, but it can never, on its own,
trigger further autonomous action.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.ai.jury import Jury
from pegase.core.audit import AuditLog
from pegase.core.autopilot import AutoPilot
from pegase.core.orchestrator import MissionContext
from pegase.core.scope import ActionType, Scope, ScopeRule
from pegase.modules.base import Finding, Module, ModuleResult


class _FakeReconConfident(Module):
    """Emits a rich, well-evidenced finding - the deterministic juror
    confirms it (severity=high + evidence + references + description)."""

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
                    severity="high",
                    evidence={"product": "nginx", "port": 80},
                    references=["https://example.com/evidence"],
                )
            ],
        )


class _FakeReconWeak(Module):
    """Emits a bare, unevidenced finding - the deterministic juror rejects
    it (severity=info, no evidence, no references, no description)."""

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
                    description="",
                    severity="info",
                )
            ],
        )


class _FakeWebBreacher(Module):
    name = "webbreacher"
    action_type = ActionType.ACTIVE

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        guard.check(targets[0], self.action_type)
        return ModuleResult(module=self.name)


def _ctx() -> MissionContext:
    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return MissionContext(
        mission_id="auto-jury", actor="tester", scope=scope,
        targets=["example.com"], parameters={},
    )


def _patch_registry(monkeypatch, recon_cls):
    registry = {"recon": recon_cls, "webbreacher": _FakeWebBreacher}
    monkeypatch.setattr("pegase.core.autopilot.available_modules", lambda: registry)
    monkeypatch.setattr("pegase.ai.selection.available_modules", lambda: registry)
    return registry


@pytest.mark.asyncio
async def test_jury_confirmed_finding_still_drives_chaining(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch, _FakeReconConfident)
    audit = AuditLog(tmp_audit_path)
    pilot = AutoPilot(audit=audit, jury=Jury(), max_rounds=3, max_modules=10)

    outcome = await pilot.run(_ctx())

    modules_run = {m for r in outcome.rounds for m in r.modules_run}
    assert modules_run == {"recon", "webbreacher"}
    first_round_verdicts = outcome.rounds[0].jury_verdicts
    assert len(first_round_verdicts) == 1
    assert first_round_verdicts[0]["confirmed"] is True


@pytest.mark.asyncio
async def test_jury_rejected_finding_is_reported_but_never_drives_chaining(
    tmp_audit_path, monkeypatch
):
    _patch_registry(monkeypatch, _FakeReconWeak)
    audit = AuditLog(tmp_audit_path)
    pilot = AutoPilot(audit=audit, jury=Jury(), max_rounds=3, max_modules=10)

    outcome = await pilot.run(_ctx())

    # webbreacher's signal *would* have matched ("http" in the finding) but
    # the jury rejected the only finding, so it must never run.
    modules_run = {m for r in outcome.rounds for m in r.modules_run}
    assert modules_run == {"recon"}
    assert outcome.stopped_reason == "no further module recommended"

    # The weak finding is still part of the final report - it is real tool
    # output and the operator should see it regardless of the jury's verdict
    # on whether it should steer the autonomous loop.
    assert len(outcome.findings) == 1
    assert outcome.findings[0].title == "Open port 80/tcp (http)"

    verdicts = outcome.rounds[0].jury_verdicts
    assert len(verdicts) == 1
    assert verdicts[0]["confirmed"] is False


@pytest.mark.asyncio
async def test_without_jury_the_weak_finding_still_drives_chaining(
    tmp_audit_path, monkeypatch
):
    """Control case: with no jury configured (the default), AutoPilot keeps
    its original behaviour and chains on every finding regardless of how
    thin its evidence is."""
    _patch_registry(monkeypatch, _FakeReconWeak)
    audit = AuditLog(tmp_audit_path)
    pilot = AutoPilot(audit=audit, max_rounds=3, max_modules=10)  # no jury

    outcome = await pilot.run(_ctx())

    modules_run = {m for r in outcome.rounds for m in r.modules_run}
    assert modules_run == {"recon", "webbreacher"}
    assert outcome.rounds[0].jury_verdicts == []


@pytest.mark.asyncio
async def test_jury_audit_entry_is_written(tmp_audit_path, monkeypatch):
    _patch_registry(monkeypatch, _FakeReconConfident)
    audit = AuditLog(tmp_audit_path)
    pilot = AutoPilot(audit=audit, jury=Jury(), max_rounds=3, max_modules=10)
    await pilot.run(_ctx())

    text = tmp_audit_path.read_text(encoding="utf-8")
    assert '"autopilot.jury"' in text
    ok, _count, error = audit.verify()
    assert ok, error

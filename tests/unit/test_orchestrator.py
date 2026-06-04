"""Orchestrator behaviour with a fake module."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.audit import AuditLog
from pegase.core.orchestrator import MissionContext, Orchestrator
from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.base import Finding, Module, ModuleResult


class _OK(Module):
    name = "ok"
    action_type = ActionType.PASSIVE

    async def run(self, *, targets, guard: ScopeGuard, parameters=None) -> ModuleResult:
        for t in targets:
            guard.check(t, self.action_type)
        return ModuleResult(
            module=self.name,
            findings=[
                Finding(
                    module=self.name,
                    target=targets[0],
                    title="ok",
                    description="ok",
                )
            ],
        )


class _Boom(Module):
    name = "boom"
    action_type = ActionType.PASSIVE

    async def run(self, *, targets, guard, parameters=None):
        raise RuntimeError("kaboom")


@pytest.mark.asyncio
async def test_orchestrator_collects_findings_and_errors(tmp_audit_path):
    audit = AuditLog(tmp_audit_path)
    scope = Scope(
        rules=[ScopeRule("example.com")],
        authorization_token="roe-x",
        starts_at=datetime.now(UTC),
    )
    ctx = MissionContext(
        mission_id="m-1",
        actor="tester",
        scope=scope,
        targets=["example.com"],
        parameters={},
    )
    orch = Orchestrator([_OK(), _Boom()], audit=audit, max_concurrency=2)
    outcome = await orch.run(ctx)
    assert len(outcome.findings) == 1
    assert outcome.findings[0].title == "ok"
    assert any("boom" in e for e in outcome.errors)
    ok, _, _ = audit.verify()
    assert ok

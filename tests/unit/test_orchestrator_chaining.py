"""Two-phase orchestrator: producers run first, consumers get their findings."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.audit import AuditLog
from pegase.core.orchestrator import MissionContext, Orchestrator
from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.base import Finding, Module, ModuleResult


class _Producer(Module):
    name = "producer"
    action_type = ActionType.PASSIVE

    async def run(self, *, targets, guard: ScopeGuard, parameters=None) -> ModuleResult:
        return ModuleResult(
            module=self.name,
            findings=[
                Finding(
                    module=self.name,
                    target=targets[0],
                    title="upstream",
                    description="upstream finding",
                    evidence={"product": "openssh", "version": "7.2"},
                )
            ],
        )


class _Consumer(Module):
    name = "consumer"
    action_type = ActionType.PASSIVE
    needs_upstream_findings = True

    def __init__(self) -> None:
        self.received: list[dict] = []

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        self.received = (parameters or {}).get("findings", [])
        return ModuleResult(module=self.name)


@pytest.mark.asyncio
async def test_consumer_receives_producer_findings(tmp_audit_path):
    audit = AuditLog(tmp_audit_path)
    scope = Scope(
        rules=[ScopeRule("example.com")],
        authorization_token="roe-x",
        starts_at=datetime.now(UTC),
    )
    consumer = _Consumer()
    orch = Orchestrator([_Producer(), consumer], audit=audit, max_concurrency=2)
    ctx = MissionContext(
        mission_id="m",
        actor="t",
        scope=scope,
        targets=["example.com"],
        parameters={},
    )
    await orch.run(ctx)
    assert len(consumer.received) == 1
    assert consumer.received[0]["evidence"]["product"] == "openssh"

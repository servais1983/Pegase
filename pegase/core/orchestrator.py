"""Mission orchestrator.

Coordinates a workflow of modules against a target list. Each module receives a
``ScopeGuard`` and reports findings + raw artifacts that are persisted through
the storage layer. Per-module concurrency is bounded so that a single mission
cannot saturate the host.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from pegase.core.audit import AuditLog, get_audit_log
from pegase.core.config import get_settings
from pegase.core.logging import get_logger
from pegase.core.scope import Scope, ScopeGuard, ScopeViolation
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)


@dataclass
class MissionContext:
    mission_id: str
    actor: str
    scope: Scope
    targets: list[str]
    parameters: dict[str, Any]


@dataclass
class MissionOutcome:
    mission_id: str
    findings: list[Finding]
    module_results: list[ModuleResult]
    errors: list[str]


class Orchestrator:
    def __init__(
        self,
        modules: list[Module],
        *,
        audit: AuditLog | None = None,
        max_concurrency: int | None = None,
    ) -> None:
        if not modules:
            raise ValueError("Orchestrator requires at least one module.")
        self._modules = modules
        self._audit = audit or get_audit_log()
        self._sem = asyncio.Semaphore(
            max_concurrency or get_settings().max_concurrent_modules
        )

    async def run(self, ctx: MissionContext) -> MissionOutcome:
        guard = ScopeGuard(
            ctx.scope,
            require_authorization=get_settings().require_authorization_token,
        )
        self._audit.append(
            action="mission.started",
            actor=ctx.actor,
            mission=ctx.mission_id,
            meta={"targets": ctx.targets, "modules": [m.name for m in self._modules]},
        )
        tasks = [self._run_module(m, ctx, guard) for m in self._modules]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        results: list[ModuleResult] = []
        errors: list[str] = []
        for module, outcome in zip(self._modules, gathered, strict=True):
            if isinstance(outcome, Exception):
                msg = f"{module.name}: {outcome!r}"
                errors.append(msg)
                log.error("module_failed", module=module.name, error=str(outcome))
                self._audit.append(
                    action="module.error",
                    actor=ctx.actor,
                    mission=ctx.mission_id,
                    target=module.name,
                    meta={"error": str(outcome)},
                )
                continue
            results.append(outcome)
            findings.extend(outcome.findings)

        self._audit.append(
            action="mission.finished",
            actor=ctx.actor,
            mission=ctx.mission_id,
            meta={"findings": len(findings), "errors": len(errors)},
        )
        return MissionOutcome(
            mission_id=ctx.mission_id,
            findings=findings,
            module_results=results,
            errors=errors,
        )

    async def _run_module(
        self, module: Module, ctx: MissionContext, guard: ScopeGuard
    ) -> ModuleResult:
        async with self._sem:
            self._audit.append(
                action="module.started",
                actor=ctx.actor,
                mission=ctx.mission_id,
                target=module.name,
            )
            try:
                result = await module.run(
                    targets=ctx.targets,
                    guard=guard,
                    parameters=ctx.parameters.get(module.name, {}),
                )
            except ScopeViolation as exc:
                self._audit.append(
                    action="scope.denied",
                    actor=ctx.actor,
                    mission=ctx.mission_id,
                    target=exc.target,
                    meta={"module": module.name, "reason": str(exc)},
                )
                raise
            self._audit.append(
                action="module.finished",
                actor=ctx.actor,
                mission=ctx.mission_id,
                target=module.name,
                meta={"findings": len(result.findings)},
            )
            return result

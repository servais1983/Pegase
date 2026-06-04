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


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "module": f.module,
        "target": f.target,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "evidence": f.evidence,
        "references": f.references,
    }


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

        # Two-phase execution: producers run in parallel, then consumers
        # (modules that declare ``needs_upstream_findings``) run sequentially
        # with the consolidated finding list injected into their parameters.
        producers = [m for m in self._modules if not m.needs_upstream_findings]
        consumers = [m for m in self._modules if m.needs_upstream_findings]

        findings: list[Finding] = []
        results: list[ModuleResult] = []
        errors: list[str] = []

        if producers:
            outcomes = await asyncio.gather(
                *[self._run_module(m, ctx, guard) for m in producers],
                return_exceptions=True,
            )
            for module, outcome in zip(producers, outcomes, strict=True):
                self._collect(module, outcome, ctx, findings, results, errors)

        for module in consumers:
            consumer_ctx = MissionContext(
                mission_id=ctx.mission_id,
                actor=ctx.actor,
                scope=ctx.scope,
                targets=ctx.targets,
                parameters={
                    **ctx.parameters,
                    module.name: {
                        **(ctx.parameters.get(module.name, {})),
                        "findings": [_finding_to_dict(f) for f in findings],
                    },
                },
            )
            try:
                outcome = await self._run_module(module, consumer_ctx, guard)
            except Exception as exc:  # noqa: BLE001
                outcome = exc
            self._collect(module, outcome, ctx, findings, results, errors)

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

    def _collect(
        self,
        module: Module,
        outcome,
        ctx: MissionContext,
        findings: list[Finding],
        results: list[ModuleResult],
        errors: list[str],
    ) -> None:
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
            return
        results.append(outcome)
        findings.extend(outcome.findings)

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

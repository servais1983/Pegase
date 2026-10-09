"""AutoPilot - bounded, audited, evidence-driven autonomous mission chaining.

Where the base :class:`~pegase.core.orchestrator.Orchestrator` runs a single,
operator-chosen set of modules, AutoPilot runs *rounds*: after every round it
looks at the findings gathered so far and asks
:func:`pegase.ai.selection.recommend_modules` what to run next, then keeps
going until one of several hard stop conditions is hit. This is PEGASE's
answer to the "autonomous agent" pentest loop popularized by tools like
PentAGI/HexStrike - with three differences that are the whole point:

  * **Bounded, not open-ended.** ``max_rounds`` and ``max_modules`` are hard
    ceilings enforced in code, not suggestions to an LLM. A run cannot spiral.
  * **Deterministic planner, LLM-optional narrator.** Which module runs next
    is decided by :mod:`pegase.ai.selection`'s evidence-pattern engine, not by
    an LLM free-associating from tool output. An LLM (if configured) may only
    summarize *after the fact*, through the grounded :class:`AIAdvisor`, which
    discards any sentence that doesn't tie back to a real finding.
  * **Every decision is audit-logged**, including modules the planner
    considered but skipped and why, through the same hash-chained audit log
    every other PEGASE action uses - so an engagement run autonomously is
    exactly as reviewable after the fact as one run by hand.

Every module invocation still goes through the mission's ``ScopeGuard``
exactly as it would under manual orchestration: AutoPilot does not grant
itself any authority the operator didn't already grant the mission.

**Optional jury-gated chaining.** Pass a :class:`~pegase.ai.jury.Jury` and
AutoPilot stops trusting a module's output at face value before letting it
steer the next round: every new finding is deliberated by the jury (the
deterministic, evidence-only juror always votes; LLM jurors, if configured,
add their vote on top), and only findings the jury *confirms* are allowed to
influence what runs next. A finding the jury rejects still appears in the
final report (it is real tool output - the operator should see it) but it
cannot, on its own, trigger further autonomous action. This is what keeps a
flaky scanner or a single noisy signal from cascading into a chain of
unnecessary active probes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pegase.ai.selection import ModuleRecommendation, recommend_modules
from pegase.core.audit import AuditLog, get_audit_log
from pegase.core.logging import get_logger
from pegase.core.orchestrator import (
    MissionContext,
    MissionOutcome,
    Orchestrator,
    finding_to_dict,
)
from pegase.core.scope import ActionType
from pegase.modules import available_modules
from pegase.modules.base import Finding, Module, ModuleResult

if TYPE_CHECKING:
    from pegase.ai.jury import Jury

log = get_logger(__name__)

DEFAULT_SEED_MODULES = ("recon",)


@dataclass
class AutoPilotRound:
    index: int
    modules_run: list[str]
    reasons: dict[str, str]
    new_findings: int
    errors: list[str] = field(default_factory=list)
    #: Present only when AutoPilot was built with a ``jury``: one entry per
    #: new finding this round, ``{"title", "confirmed", "confidence"}``.
    jury_verdicts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "modules_run": self.modules_run,
            "reasons": self.reasons,
            "new_findings": self.new_findings,
            "errors": self.errors,
            "jury_verdicts": self.jury_verdicts,
        }


@dataclass
class AutoPilotOutcome:
    mission_id: str
    rounds: list[AutoPilotRound]
    findings: list[Finding]
    module_results: list[ModuleResult]
    errors: list[str]
    stopped_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "rounds": [r.to_dict() for r in self.rounds],
            "findings": [finding_to_dict(f) for f in self.findings],
            "errors": self.errors,
            "stopped_reason": self.stopped_reason,
        }


class AutoPilot:
    """Drives the Orchestrator through successive, self-selected rounds."""

    def __init__(
        self,
        *,
        audit: AuditLog | None = None,
        max_rounds: int = 6,
        max_modules: int = 20,
        max_concurrency: int | None = None,
        seed_modules: tuple[str, ...] = DEFAULT_SEED_MODULES,
        max_recommendations_per_round: int = 3,
        jury: Jury | None = None,
    ) -> None:
        if max_rounds < 1:
            raise ValueError("max_rounds must be >= 1")
        if max_modules < 1:
            raise ValueError("max_modules must be >= 1")
        self._audit = audit or get_audit_log()
        self._max_rounds = max_rounds
        self._max_modules = max_modules
        self._max_concurrency = max_concurrency
        self._seed_modules = seed_modules
        self._max_recs = max_recommendations_per_round
        self._jury = jury

    async def run(self, ctx: MissionContext) -> AutoPilotOutcome:
        registry = available_modules()
        allowed_actions = ctx.scope.allowed_actions

        seed = [m for m in self._seed_modules if m in registry]
        if not seed:
            raise ValueError(
                f"no valid seed modules in {self._seed_modules!r}; "
                f"available: {sorted(registry)}"
            )

        self._audit.append(
            action="autopilot.started",
            actor=ctx.actor,
            mission=ctx.mission_id,
            meta={
                "seed_modules": list(seed),
                "max_rounds": self._max_rounds,
                "max_modules": self._max_modules,
            },
        )

        rounds: list[AutoPilotRound] = []
        all_findings: list[Finding] = []
        planning_findings: list[Finding] = []
        all_results: list[ModuleResult] = []
        all_errors: list[str] = []
        already_run: set[str] = set()
        next_modules: list[str] = list(seed)
        reasons: dict[str, str] = {m: "seed module" for m in seed}
        stopped_reason = "max_rounds reached"

        for round_index in range(1, self._max_rounds + 1):
            if not next_modules:
                stopped_reason = "no further module recommended"
                break
            if len(already_run) >= self._max_modules:
                stopped_reason = "max_modules budget exhausted"
                break

            budget_left = self._max_modules - len(already_run)
            round_modules = next_modules[:budget_left]
            instances = [registry[m]() for m in round_modules]

            round_ctx = MissionContext(
                mission_id=ctx.mission_id,
                actor=ctx.actor,
                scope=ctx.scope,
                targets=ctx.targets,
                parameters=ctx.parameters,
            )
            orchestrator = Orchestrator(
                instances, audit=self._audit, max_concurrency=self._max_concurrency
            )
            outcome: MissionOutcome = await orchestrator.run(round_ctx)

            already_run.update(round_modules)
            all_findings.extend(outcome.findings)
            all_results.extend(outcome.module_results)
            all_errors.extend(outcome.errors)

            jury_verdicts: list[dict[str, Any]] = []
            if self._jury is not None:
                for f in outcome.findings:
                    verdict = await self._jury.deliberate(finding_to_dict(f))
                    jury_verdicts.append(verdict.to_dict())
                    if verdict.confirmed:
                        planning_findings.append(f)
                self._audit.append(
                    action="autopilot.jury",
                    actor=ctx.actor,
                    mission=ctx.mission_id,
                    meta={
                        "round": round_index,
                        "confirmed": sum(1 for v in jury_verdicts if v["confirmed"]),
                        "rejected": sum(1 for v in jury_verdicts if not v["confirmed"]),
                    },
                )
            else:
                planning_findings.extend(outcome.findings)

            rounds.append(
                AutoPilotRound(
                    index=round_index,
                    modules_run=round_modules,
                    reasons={m: reasons.get(m, "") for m in round_modules},
                    new_findings=len(outcome.findings),
                    errors=outcome.errors,
                    jury_verdicts=jury_verdicts,
                )
            )
            self._audit.append(
                action="autopilot.round_finished",
                actor=ctx.actor,
                mission=ctx.mission_id,
                meta={
                    "round": round_index,
                    "modules_run": round_modules,
                    "new_findings": len(outcome.findings),
                    "errors": outcome.errors,
                },
            )

            recs = self._next_recommendations(
                planning_findings, ctx, registry, allowed_actions, already_run
            )
            next_modules = [r.module for r in recs]
            reasons = {r.module: r.reason for r in recs}
            if not next_modules:
                stopped_reason = "no further module recommended"
                self._audit.append(
                    action="autopilot.plan",
                    actor=ctx.actor,
                    mission=ctx.mission_id,
                    meta={"round": round_index + 1, "decision": "stop", "reason": stopped_reason},
                )
                break
            self._audit.append(
                action="autopilot.plan",
                actor=ctx.actor,
                mission=ctx.mission_id,
                meta={
                    "round": round_index + 1,
                    "decision": "continue",
                    "candidates": [r.to_dict() for r in recs],
                },
            )
        else:
            stopped_reason = "max_rounds reached"

        self._audit.append(
            action="autopilot.finished",
            actor=ctx.actor,
            mission=ctx.mission_id,
            meta={
                "rounds": len(rounds),
                "modules_run": sorted(already_run),
                "findings": len(all_findings),
                "stopped_reason": stopped_reason,
            },
        )

        return AutoPilotOutcome(
            mission_id=ctx.mission_id,
            rounds=rounds,
            findings=all_findings,
            module_results=all_results,
            errors=all_errors,
            stopped_reason=stopped_reason,
        )

    def _next_recommendations(
        self,
        findings: list[Finding],
        ctx: MissionContext,
        registry: dict[str, type[Module]],
        allowed_actions: set[ActionType],
        already_run: set[str],
    ) -> list[ModuleRecommendation]:
        finding_dicts = [finding_to_dict(f) for f in findings]
        recs = recommend_modules(finding_dicts, ctx.targets, already_run=already_run)
        eligible = [
            r
            for r in recs
            if r.module in registry
            and registry[r.module].autopilot_ready
            and registry[r.module].action_type in allowed_actions
        ]
        return eligible[: self._max_recs]

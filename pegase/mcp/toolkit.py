"""Governed toolkit backing the PEGASE MCP server.

These functions are the security spine of the MCP integration. An AI agent
never touches a module directly: it calls one of these tools, and every call

  * is written to the hash-chained audit log as ``mcp.tool.invoked`` (tagged
    with the agent as actor) *before* anything runs,
  * is gated by Rules-of-Engagement — a mission with no authorization token is
    denied and the denial is audited,
  * defaults to *passive only*; ``allow_active`` / ``allow_exploit`` must be
    explicitly requested, so an autonomous agent gets least privilege,
  * re-validates every target against the scope guard inside the orchestrator,
    so caller-supplied targets can never escape the agreed scope.

The functions return plain, JSON-serialisable dicts (never raise for policy
denials) so an agent receives a structured, actionable result. Async variants
drive the orchestrator; thin sync wrappers exist for the CLI and tests.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from pegase.core.audit import AuditLog, get_audit_log
from pegase.core.config import get_settings
from pegase.core.orchestrator import MissionContext, Orchestrator
from pegase.core.scope import ActionType, Scope, ScopeRule
from pegase.modules import available_modules

DEFAULT_ACTOR = "mcp-agent"


# --------------------------------------------------------------------------- #
# Read-only discovery tools.
# --------------------------------------------------------------------------- #
def list_modules() -> dict[str, Any]:
    """List the modules an agent may request, with their action posture."""
    registry = available_modules()
    return {
        "modules": [
            {
                "name": cls.name,
                "description": cls.description,
                "action_type": cls.action_type.value,
                "needs_upstream_findings": cls.needs_upstream_findings,
            }
            for cls in registry.values()
        ]
    }


def list_scenarios() -> dict[str, Any]:
    """List the built-in ThreatSim scenarios (named multi-stage kill-chains)."""
    from pegase.core.scenarios import list_builtin_scenarios

    return {
        "scenarios": [
            {"name": name, "description": desc}
            for name, desc in list_builtin_scenarios().items()
        ]
    }


# --------------------------------------------------------------------------- #
# Governed execution tools.
# --------------------------------------------------------------------------- #
def _resolve_actions(allow_active: bool, allow_exploit: bool) -> set[ActionType]:
    actions = {ActionType.PASSIVE}
    if allow_active:
        actions.add(ActionType.ACTIVE)
    if allow_exploit:
        actions.add(ActionType.EXPLOIT)
    return actions


def _finding_dicts(findings: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "module": f.module,
            "target": f.target,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "evidence": f.evidence,
            "references": f.references,
        }
        for f in findings
    ]


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def _maybe_report(findings: list[dict[str, Any]], report_format: str) -> str | None:
    fmt = (report_format or "").lower()
    if fmt == "sarif":
        import json

        from pegase.reporting.generator import build_sarif_report

        return json.dumps(build_sarif_report(findings))
    if fmt == "csv":
        from pegase.reporting.generator import build_csv_report

        return build_csv_report(findings)
    return None


async def _execute(
    *,
    tool: str,
    targets: list[str],
    modules: list[str],
    parameters: dict[str, Any],
    authorization: str | None,
    allow_active: bool,
    allow_exploit: bool,
    scope_patterns: list[str] | None,
    actor: str,
    report_format: str,
    audit: AuditLog,
) -> dict[str, Any]:
    settings = get_settings()
    actions = _resolve_actions(allow_active, allow_exploit)

    # 1) Record the agent's request *before* acting on it.
    audit.append(
        action="mcp.tool.invoked",
        actor=actor,
        target=",".join(targets),
        meta={
            "tool": tool,
            "modules": modules,
            "actions": sorted(a.value for a in actions),
            "authorization_provided": bool(authorization),
            "initiator": "ai-agent",
        },
    )

    # 2) Rules-of-Engagement gate: refuse (and audit) an unauthorized mission.
    if settings.require_authorization_token and not authorization:
        audit.append(
            action="mcp.denied",
            actor=actor,
            target=",".join(targets),
            meta={"tool": tool, "reason": "missing authorization token (RoE)"},
        )
        return {
            "status": "denied",
            "reason": (
                "Rules of Engagement require an authorization token before any "
                "module may run. Supply 'authorization'."
            ),
        }

    # 3) Reject unknown modules with a structured, agent-friendly error.
    registry = available_modules()
    unknown = [m for m in modules if m not in registry]
    if unknown:
        audit.append(
            action="mcp.rejected",
            actor=actor,
            meta={"tool": tool, "unknown_modules": unknown},
        )
        return {
            "status": "error",
            "reason": f"unknown modules: {unknown}",
            "known_modules": sorted(registry.keys()),
        }
    if not modules:
        return {"status": "error", "reason": "no modules selected"}

    # 4) Build the scope (defaults to the target set) and run under the guard.
    patterns = scope_patterns or targets
    scope = Scope(
        rules=[ScopeRule(pattern=p) for p in patterns],
        allowed_actions=actions,
        starts_at=datetime.now(UTC),
        authorization_token=authorization,
    )
    mission_id = "mcp-" + datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    ctx = MissionContext(
        mission_id=mission_id,
        actor=actor,
        scope=scope,
        targets=targets,
        parameters=parameters,
    )
    orchestrator = Orchestrator(
        [registry[m]() for m in modules], audit=audit
    )
    outcome = await orchestrator.run(ctx)

    findings = _finding_dicts(outcome.findings)
    ok, lines, error = audit.verify()
    result: dict[str, Any] = {
        "status": "ok",
        "mission_id": outcome.mission_id,
        "actor": actor,
        "targets": targets,
        "modules": modules,
        "allowed_actions": sorted(a.value for a in actions),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": _severity_counts(findings),
        },
        "errors": outcome.errors,
        "audit": {"verified": ok, "entries": lines, "error": error},
    }
    report = _maybe_report(findings, report_format)
    if report is not None:
        result["report"] = report
        result["report_format"] = report_format.lower()
    return result


async def run_scan_async(
    *,
    targets: list[str],
    modules: list[str] | None = None,
    authorization: str | None = None,
    allow_active: bool = False,
    allow_exploit: bool = False,
    scope_patterns: list[str] | None = None,
    actor: str = DEFAULT_ACTOR,
    report_format: str = "",
    audit: AuditLog | None = None,
) -> dict[str, Any]:
    """Run an ad-hoc governed scan requested by an agent."""
    return await _execute(
        tool="run_scan",
        targets=list(targets),
        modules=list(modules or ["recon"]),
        parameters={},
        authorization=authorization,
        allow_active=allow_active,
        allow_exploit=allow_exploit,
        scope_patterns=scope_patterns,
        actor=actor,
        report_format=report_format,
        audit=audit or get_audit_log(),
    )


async def run_scenario_async(
    *,
    targets: list[str],
    scenario: str,
    authorization: str | None = None,
    allow_active: bool = False,
    allow_exploit: bool = False,
    scope_patterns: list[str] | None = None,
    actor: str = DEFAULT_ACTOR,
    report_format: str = "",
    audit: AuditLog | None = None,
) -> dict[str, Any]:
    """Run a named ThreatSim scenario under the same governance guarantees."""
    from pegase.core.scenarios import load_scenario

    audit = audit or get_audit_log()
    try:
        scen = load_scenario(scenario)
    except (FileNotFoundError, ValueError) as exc:
        return {"status": "error", "reason": f"scenario load failed: {exc}"}
    errors = scen.validate()
    if errors:
        return {"status": "error", "reason": "invalid scenario", "details": errors}

    return await _execute(
        tool="run_scenario",
        targets=list(targets),
        modules=scen.all_modules(),
        parameters=scen.merged_parameters(),
        authorization=authorization,
        allow_active=allow_active,
        allow_exploit=allow_exploit,
        scope_patterns=scope_patterns,
        actor=actor,
        report_format=report_format,
        audit=audit,
    )


async def advise_async(
    *,
    findings: list[dict[str, Any]],
    actor: str = DEFAULT_ACTOR,
    audit: AuditLog | None = None,
) -> dict[str, Any]:
    """Run the grounded, offline-by-default AI advisor over findings."""
    from pegase.ai.advisor import AIAdvisor

    audit = audit or get_audit_log()
    audit.append(
        action="mcp.tool.invoked",
        actor=actor,
        meta={"tool": "advise", "findings": len(findings), "initiator": "ai-agent"},
    )
    analysis = await AIAdvisor().analyze(list(findings))
    return {"status": "ok", "analysis": analysis.to_dict()}


def verify_audit(audit: AuditLog | None = None) -> dict[str, Any]:
    """Verify the tamper-evident audit chain and report the result."""
    audit = audit or get_audit_log()
    ok, lines, error = audit.verify()
    return {"status": "ok", "verified": ok, "entries": lines, "error": error}


# --------------------------------------------------------------------------- #
# Sync wrappers (CLI / tests). The MCP server uses the async variants.
# --------------------------------------------------------------------------- #
def run_scan(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_scan_async(**kwargs))


def run_scenario(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_scenario_async(**kwargs))


def advise(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(advise_async(**kwargs))

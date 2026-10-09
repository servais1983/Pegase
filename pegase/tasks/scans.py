"""Celery task that runs a mission end-to-end.

Celery workers are sync, so we bridge to the async orchestrator via
``asyncio.run``. The task uses a *sync* SQLAlchemy session to load the
mission row and persist findings; the orchestrator and modules themselves
run on the asyncio loop spawned for the task.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from pegase.core.audit import get_audit_log
from pegase.core.config import get_settings
from pegase.core.logging import configure_logging, get_logger
from pegase.core.orchestrator import MissionContext, Orchestrator
from pegase.core.scope import ActionType, Scope, ScopeRule
from pegase.db.models import Finding as FindingModel
from pegase.db.models import Mission, MissionStatus, Severity
from pegase.modules import available_modules
from pegase.tasks.celery_app import celery_app

log = get_logger(__name__)


def _sync_session() -> Session:
    settings = get_settings()
    engine = create_engine(settings.database_sync_url, pool_pre_ping=True, future=True)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)()


def _scope_from_mission(mission: Mission) -> Scope:
    return Scope(
        rules=[
            ScopeRule(pattern=r["pattern"], include=r.get("include", True))
            for r in (mission.scope_rules or [])
        ],
        allowed_actions={ActionType(a) for a in (mission.allowed_actions or ["passive"])},
        starts_at=mission.starts_at,
        ends_at=mission.ends_at,
        authorization_token=mission.authorization_token,
    )


def _persist_findings(db: Session, mission: Mission, findings) -> None:
    for f in findings:
        db.add(
            FindingModel(
                mission_id=mission.id,
                module=f.module,
                target=f.target,
                title=f.title,
                description=f.description,
                severity=Severity(f.severity),
                evidence=f.evidence,
                references=f.references,
                discovered_at=datetime.now(UTC),
            )
        )


@celery_app.task(name="pegase.run_mission", bind=True)
def run_mission_task(self, mission_id: str, modules: list[str], actor: str) -> dict:
    configure_logging()
    log.info("task_start", mission=mission_id, modules=modules, actor=actor)
    db = _sync_session()
    try:
        mission = db.scalar(select(Mission).where(Mission.id == mission_id))
        if not mission:
            return {"ok": False, "error": "mission not found"}

        registry = available_modules()
        module_instances = [registry[m]() for m in modules]

        ctx = MissionContext(
            mission_id=mission.id,
            actor=actor,
            scope=_scope_from_mission(mission),
            targets=list(mission.targets or []),
            parameters=dict(mission.parameters or {}),
        )
        orchestrator = Orchestrator(module_instances)
        outcome = asyncio.run(orchestrator.run(ctx))

        _persist_findings(db, mission, outcome.findings)
        mission.status = (
            MissionStatus.FAILED if outcome.errors else MissionStatus.COMPLETED
        )
        mission.updated_at = datetime.now(UTC)
        db.commit()

        get_audit_log().append(
            action="mission.persisted",
            actor=actor,
            mission=mission.id,
            meta={
                "findings": len(outcome.findings),
                "errors": outcome.errors,
                "task_id": self.request.id,
            },
        )
        return {
            "ok": True,
            "findings": len(outcome.findings),
            "errors": outcome.errors,
        }
    except Exception as exc:  # noqa: BLE001
        log.exception("task_failed", error=str(exc))
        db.rollback()
        mission = db.scalar(select(Mission).where(Mission.id == mission_id))
        if mission:
            mission.status = MissionStatus.FAILED
            db.commit()
        get_audit_log().append(
            action="mission.failed",
            actor=actor,
            mission=mission_id,
            meta={"error": str(exc)},
        )
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="pegase.run_autopilot", bind=True)
def run_autopilot_task(
    self,
    mission_id: str,
    seed_modules: list[str],
    actor: str,
    *,
    max_rounds: int = 6,
    max_modules: int = 20,
    use_jury: bool = False,
) -> dict:
    """Run AutoPilot end-to-end for a persisted mission.

    Mirrors :func:`run_mission_task`'s persistence (findings go into the
    ``findings`` table exactly the same way), plus it stores the round-by-
    round summary on ``mission.autopilot_state`` so the API/dashboard can
    show what the planner did and why, after the fact.
    """
    configure_logging()
    log.info(
        "autopilot_task_start",
        mission=mission_id,
        seed_modules=seed_modules,
        actor=actor,
    )
    db = _sync_session()
    try:
        mission = db.scalar(select(Mission).where(Mission.id == mission_id))
        if not mission:
            return {"ok": False, "error": "mission not found"}

        from pegase.core.autopilot import AutoPilot

        jury = None
        if use_jury:
            from pegase.ai.jury import Jury
            from pegase.ai.providers import get_provider

            jury = Jury(providers=[get_provider(get_settings())])

        ctx = MissionContext(
            mission_id=mission.id,
            actor=actor,
            scope=_scope_from_mission(mission),
            targets=list(mission.targets or []),
            parameters=dict(mission.parameters or {}),
        )
        pilot = AutoPilot(
            seed_modules=tuple(seed_modules),
            max_rounds=max_rounds,
            max_modules=max_modules,
            jury=jury,
        )
        outcome = asyncio.run(pilot.run(ctx))

        _persist_findings(db, mission, outcome.findings)
        mission.autopilot_state = {
            "rounds": [r.to_dict() for r in outcome.rounds],
            "stopped_reason": outcome.stopped_reason,
            "task_id": self.request.id,
        }
        mission.status = (
            MissionStatus.FAILED if outcome.errors else MissionStatus.COMPLETED
        )
        mission.updated_at = datetime.now(UTC)
        db.commit()

        get_audit_log().append(
            action="mission.persisted",
            actor=actor,
            mission=mission.id,
            meta={
                "findings": len(outcome.findings),
                "errors": outcome.errors,
                "rounds": len(outcome.rounds),
                "stopped_reason": outcome.stopped_reason,
                "task_id": self.request.id,
            },
        )
        return {
            "ok": True,
            "findings": len(outcome.findings),
            "errors": outcome.errors,
            "rounds": len(outcome.rounds),
            "stopped_reason": outcome.stopped_reason,
        }
    except Exception as exc:  # noqa: BLE001
        log.exception("autopilot_task_failed", error=str(exc))
        db.rollback()
        mission = db.scalar(select(Mission).where(Mission.id == mission_id))
        if mission:
            mission.status = MissionStatus.FAILED
            db.commit()
        get_audit_log().append(
            action="mission.failed",
            actor=actor,
            mission=mission_id,
            meta={"error": str(exc)},
        )
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()

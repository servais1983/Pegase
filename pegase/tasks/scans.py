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

        scope = Scope(
            rules=[
                ScopeRule(pattern=r["pattern"], include=r.get("include", True))
                for r in (mission.scope_rules or [])
            ],
            allowed_actions={
                ActionType(a) for a in (mission.allowed_actions or ["passive"])
            },
            starts_at=mission.starts_at,
            ends_at=mission.ends_at,
            authorization_token=mission.authorization_token,
        )
        ctx = MissionContext(
            mission_id=mission.id,
            actor=actor,
            scope=scope,
            targets=list(mission.targets or []),
            parameters=dict(mission.parameters or {}),
        )
        orchestrator = Orchestrator(module_instances)
        outcome = asyncio.run(orchestrator.run(ctx))

        for f in outcome.findings:
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

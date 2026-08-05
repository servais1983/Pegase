"""AI ("Neuro") routes - grounded advisor, module recommendation, jury.

These endpoints operate over a mission's stored findings. They never touch a
target, so they only require an authenticated user (not an authorization token);
the underlying findings were already produced through the scope-guarded pipeline.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pegase.ai.advisor import AIAdvisor
from pegase.ai.jury import Jury
from pegase.ai.providers import available_providers, get_provider
from pegase.ai.selection import recommend_modules
from pegase.api.deps import current_user
from pegase.core.audit import get_audit_log
from pegase.core.config import get_settings
from pegase.db.models import Finding, Mission, User
from pegase.db.session import get_session

router = APIRouter(prefix="/ai", tags=["ai"])


async def _mission_findings(mission_id: str, db: AsyncSession) -> tuple[Mission, list[dict]]:
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    rows = list(
        await db.scalars(select(Finding).where(Finding.mission_id == mission_id))
    )
    findings = [
        {
            "id": f.id,
            "module": f.module,
            "target": f.target,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "evidence": f.evidence,
            "references": f.references,
        }
        for f in rows
    ]
    return mission, findings


@router.get("/providers")
async def providers(user: User = Depends(current_user)) -> dict:
    settings = get_settings()
    provider = get_provider(settings)
    return {
        "available": available_providers(),
        "configured": settings.ai_provider,
        "effective": provider.name,
        "offline": provider.offline,
        "jury_enabled": settings.ai_jury_enabled,
    }


@router.get("/missions/{mission_id}/advise")
async def advise(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    mission, findings = await _mission_findings(mission_id, db)
    analysis = await AIAdvisor().analyze(findings)
    get_audit_log().append(
        action="ai.advise",
        actor=user.username,
        mission=mission_id,
        meta={"risk_score": analysis.risk_score, "provider": analysis.provider},
    )
    return {"mission_id": mission_id, "analysis": analysis.to_dict()}


@router.get("/missions/{mission_id}/recommend")
async def recommend(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    mission, findings = await _mission_findings(mission_id, db)
    already = {f["module"] for f in findings}
    recs = recommend_modules(findings, mission.targets or [], already_run=already)
    return {"mission_id": mission_id, "recommendations": [r.to_dict() for r in recs]}


@router.get("/missions/{mission_id}/jury")
async def jury(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    _mission, findings = await _mission_findings(mission_id, db)
    settings = get_settings()
    providers_list = [get_provider(settings)] if settings.ai_jury_enabled else []
    panel = Jury(providers_list)
    # Only adjudicate actionable findings (skip pure info noise).
    actionable = [f for f in findings if f["severity"] != "info"]
    verdicts = [await panel.deliberate(f) for f in actionable]
    return {
        "mission_id": mission_id,
        "verdicts": [v.to_dict() for v in verdicts],
    }

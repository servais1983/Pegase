"""Reporting routes - JSON and HTML export."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pegase.api.deps import current_user
from pegase.db.models import Finding, Mission, User
from pegase.db.session import get_session
from pegase.reporting.generator import build_html_report, build_json_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{mission_id}.json")
async def json_report(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> JSONResponse:
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "mission not found")
    findings = list(
        await db.scalars(
            select(Finding)
            .where(Finding.mission_id == mission_id)
            .order_by(Finding.severity)
        )
    )
    return JSONResponse(build_json_report(mission, findings))


@router.get("/{mission_id}.html", response_class=HTMLResponse)
async def html_report(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "mission not found")
    findings = list(
        await db.scalars(
            select(Finding)
            .where(Finding.mission_id == mission_id)
            .order_by(Finding.severity)
        )
    )
    return HTMLResponse(build_html_report(mission, findings))

"""Finding routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pegase.api.deps import current_user
from pegase.api.schemas import FindingOut
from pegase.db.models import Finding, User
from pegase.db.session import get_session

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
async def list_findings(
    mission_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> list[Finding]:
    stmt = select(Finding).order_by(Finding.discovered_at.desc()).limit(500)
    if mission_id:
        stmt = stmt.where(Finding.mission_id == mission_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    return list(await db.scalars(stmt))

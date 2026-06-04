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


@router.get("/{mission_id}/graph.json")
async def attack_graph(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> JSONResponse:
    """Return the attack-path graph built by PostXploit, if present.

    Falls back to a graph derived from all findings when PostXploit did not
    run, so the visualization is always available.
    """
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "mission not found")
    findings = list(
        await db.scalars(select(Finding).where(Finding.mission_id == mission_id))
    )
    # Prefer the PostXploit graph stored in evidence.
    for f in findings:
        if f.module == "postxploit" and isinstance(f.evidence, dict):
            graph = f.evidence.get("graph")
            if graph:
                return JSONResponse(graph)
    # Fallback: synthesise nodes from findings.
    from pegase.modules.postxploit import PostXploit, _host_of  # noqa: PLC0415

    sev_w = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    nodes: dict[str, dict] = {}
    for f in findings:
        host = _host_of(f.target)
        if not host:
            continue
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        n = nodes.setdefault(host, {"id": host, "max_severity": "info", "findings": 0})
        n["findings"] += 1
        if sev_w.get(sev, 0) > sev_w.get(n["max_severity"], 0):
            n["max_severity"] = sev
    _ = PostXploit  # keep import meaningful
    return JSONResponse({"nodes": list(nodes.values()), "edges": []})


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

"""Mission routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pegase.api.deps import current_user
from pegase.api.schemas import (
    MissionCreate,
    MissionOut,
    MissionRunRequest,
    MissionRunResponse,
    MissionUpdate,
)
from pegase.core.audit import get_audit_log
from pegase.db.models import Mission, MissionStatus, User
from pegase.db.session import get_session
from pegase.modules import available_modules

router = APIRouter(prefix="/missions", tags=["missions"])


@router.get("", response_model=list[MissionOut])
async def list_missions(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> list[Mission]:
    missions = await db.scalars(select(Mission).order_by(Mission.created_at.desc()))
    return list(missions)


@router.post("", response_model=MissionOut, status_code=status.HTTP_201_CREATED)
async def create_mission(
    payload: MissionCreate,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> Mission:
    mission = Mission(
        name=payload.name,
        client=payload.client,
        targets=payload.targets,
        scope_rules=[r.model_dump() for r in payload.scope_rules],
        allowed_actions=payload.allowed_actions,
        parameters=payload.parameters,
        authorization_token=payload.authorization_token,
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
        created_by=user.id,
        status=(
            MissionStatus.AUTHORIZED
            if payload.authorization_token
            else MissionStatus.DRAFT
        ),
    )
    db.add(mission)
    await db.flush()
    get_audit_log().append(
        action="mission.created",
        actor=user.username,
        mission=mission.id,
        meta={"name": mission.name, "targets": mission.targets},
    )
    return mission


@router.get("/{mission_id}", response_model=MissionOut)
async def get_mission(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> Mission:
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    return mission


@router.patch("/{mission_id}", response_model=MissionOut)
async def update_mission(
    mission_id: str,
    payload: MissionUpdate,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> Mission:
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    if mission.status == MissionStatus.RUNNING:
        raise HTTPException(status.HTTP_409_CONFLICT, "mission is running")
    data = payload.model_dump(exclude_unset=True)
    if "scope_rules" in data:
        data["scope_rules"] = [r if isinstance(r, dict) else r.model_dump() for r in data["scope_rules"]]
    for k, v in data.items():
        setattr(mission, k, v)
    if mission.authorization_token and mission.status == MissionStatus.DRAFT:
        mission.status = MissionStatus.AUTHORIZED
    get_audit_log().append(
        action="mission.updated",
        actor=user.username,
        mission=mission.id,
        meta=list(data.keys()),
    )
    return mission


@router.delete(
    "/{mission_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None
)
async def delete_mission(
    mission_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
):
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    if mission.status == MissionStatus.RUNNING:
        raise HTTPException(status.HTTP_409_CONFLICT, "mission is running")
    await db.delete(mission)
    get_audit_log().append(
        action="mission.deleted",
        actor=user.username,
        mission=mission_id,
    )


@router.post("/{mission_id}/run", response_model=MissionRunResponse)
async def run_mission(
    mission_id: str,
    payload: MissionRunRequest,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> MissionRunResponse:
    mission = await db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    if mission.status not in (MissionStatus.AUTHORIZED, MissionStatus.COMPLETED, MissionStatus.FAILED):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"mission must be in 'authorized' state, currently '{mission.status.value}'",
        )
    if not mission.targets:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "mission has no targets")
    if not mission.authorization_token:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "mission requires an authorization token"
        )

    modules = payload.modules
    if payload.scenario:
        from pegase.core.scenarios import load_scenario

        try:
            scen = load_scenario(payload.scenario)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        errors = scen.validate()
        if errors:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "; ".join(errors))
        modules = scen.all_modules()
        # Merge scenario parameters into the mission parameters for this run.
        merged = dict(mission.parameters or {})
        for mod, mp in scen.merged_parameters().items():
            merged.setdefault(mod, {}).update(mp)
        mission.parameters = merged

    unknown = set(modules) - set(available_modules().keys())
    if unknown:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"unknown modules: {sorted(unknown)}"
        )

    mission.status = MissionStatus.RUNNING
    await db.flush()

    from pegase.tasks.scans import run_mission_task  # local import to avoid cycle

    task = run_mission_task.delay(mission_id, modules, user.username)
    get_audit_log().append(
        action="mission.queued",
        actor=user.username,
        mission=mission.id,
        meta={"task_id": task.id, "modules": payload.modules},
    )
    return MissionRunResponse(mission_id=mission.id, task_id=task.id)

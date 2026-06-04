"""System / observability routes."""

from __future__ import annotations

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from pegase.db.session import get_engine
from pegase.modules import available_modules

router = APIRouter(tags=["system"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz() -> dict:
    engine = get_engine()
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return {"status": "ready"}


@router.get("/modules")
async def modules() -> dict:
    return {
        "modules": [
            {
                "name": cls.name,
                "description": cls.description,
                "action_type": cls.action_type.value,
            }
            for cls in available_modules().values()
        ]
    }


@router.get("/metrics")
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

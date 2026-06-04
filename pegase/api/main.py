"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from pegase.api.routes import auth, findings, missions, reports, system, tracking
from pegase.core.config import get_settings
from pegase.core.logging import configure_logging, get_logger
from pegase.core.scope import ScopeViolation
from pegase.db.models import Mission
from pegase.db.session import session_scope

log = get_logger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    settings = get_settings()
    settings.ensure_runtime_dirs()
    log.info("pegase_started", env=settings.environment)
    yield
    log.info("pegase_stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="PEGASE API",
        version="0.1.0",
        description="Penetration Engagement for Global Attack Simulation & Evasion",
        lifespan=lifespan,
    )

    # Use Redis-backed storage only in production; fall back to in-memory
    # otherwise so unit tests (and `pegase-api` without a running Redis)
    # do not crash on a refused connection.
    storage_uri = settings.redis_url if settings.is_production else "memory://"
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["120/minute"],
        storage_uri=storage_uri,
        headers_enabled=True,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(ScopeViolation)
    async def _scope_handler(request: Request, exc: ScopeViolation):
        return JSONResponse(
            status_code=403,
            content={
                "error": "scope_violation",
                "message": str(exc),
                "target": exc.target,
                "action": exc.action.value,
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def _db_handler(request: Request, exc: SQLAlchemyError):
        log.error("db_error", error=str(exc))
        return JSONResponse(status_code=500, content={"error": "database_error"})

    v1 = "/api/v1"
    app.include_router(auth.router, prefix=v1)
    app.include_router(missions.router, prefix=v1)
    app.include_router(findings.router, prefix=v1)
    app.include_router(reports.router, prefix=v1)
    app.include_router(system.router)
    app.include_router(tracking.router)  # public, unauthenticated

    if FRONTEND_DIR.exists():
        app.mount(
            "/static",
            StaticFiles(directory=FRONTEND_DIR / "static"),
            name="static",
        )
        templates = Jinja2Templates(directory=FRONTEND_DIR / "templates")

        @app.get("/", response_class=HTMLResponse, include_in_schema=False)
        async def dashboard(request: Request):
            async with session_scope() as db:
                missions_rows = list(
                    await db.scalars(
                        select(Mission).order_by(Mission.created_at.desc()).limit(50)
                    )
                )
            return templates.TemplateResponse(
                request,
                "dashboard.html",
                {"missions": missions_rows, "version": "0.1.0"},
            )

    return app


app = create_app()


def run() -> None:
    """Entry point for the ``pegase-api`` console script."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "pegase.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    run()

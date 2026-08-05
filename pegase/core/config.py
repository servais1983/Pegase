"""Configuration loader for PEGASE.

All settings are read from environment variables (12-factor) with sensible
defaults for local development. Production deployments MUST override at minimum
PEGASE_SECRET_KEY and PEGASE_DATABASE_URL.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PEGASE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    secret_key: str = Field(
        default="CHANGE-ME-IN-PRODUCTION-this-is-not-safe",
        description="Used to sign JWTs and audit chain. MUST be set in production.",
    )
    jwt_algorithm: str = Field(default="HS256")
    jwt_expire_minutes: int = Field(default=60 * 8)
    refresh_token_expire_days: int = Field(default=14)

    database_url: str = Field(
        default="postgresql+asyncpg://pegase:pegase@localhost:5432/pegase",
    )
    database_sync_url: str = Field(
        default="postgresql+psycopg2://pegase:pegase@localhost:5432/pegase",
        description="Used by Alembic and by Celery workers.",
    )

    redis_url: str = Field(default="redis://localhost:6379/0")
    celery_broker_url: str = Field(default="redis://localhost:6379/1")
    celery_result_backend: str = Field(default="redis://localhost:6379/2")

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    audit_log_path: Path = Field(default=Path("/var/lib/pegase/audit.log"))
    artifact_dir: Path = Field(default=Path("/var/lib/pegase/artifacts"))

    require_authorization_token: bool = Field(
        default=True,
        description=(
            "When True, every mission must include a signed authorization token "
            "before any active module can execute."
        ),
    )
    max_concurrent_modules: int = Field(default=8)

    # --- AI layer -----------------------------------------------------------
    ai_provider: str = Field(
        default="offline",
        description="LLM backend: offline | anthropic | openai | ollama.",
    )
    ai_model: str = Field(default="", description="Model id (provider default when empty).")
    ai_api_key: str = Field(default="", description="API key for cloud providers.")
    ai_base_url: str = Field(default="", description="Override base URL (self-hosted / gateway).")
    ai_jury_enabled: bool = Field(default=False, description="Enable multi-model finding jury.")
    ai_max_tokens: int = Field(default=1024)
    ai_timeout_seconds: float = Field(default=30.0)

    @field_validator("environment")
    @classmethod
    def _env_lower(cls, v: str) -> str:
        return v.lower()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def ensure_runtime_dirs(self) -> None:
        for path in (self.audit_log_path.parent, self.artifact_dir):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    if settings.is_production and settings.secret_key.startswith("CHANGE-ME"):
        raise RuntimeError(
            "PEGASE_SECRET_KEY must be set to a strong random value in production."
        )
    return settings

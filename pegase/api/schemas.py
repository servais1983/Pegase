"""Pydantic v2 request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str
    password: str = Field(min_length=10)
    role: str = "operator"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class ScopeRuleIn(BaseModel):
    pattern: str
    include: bool = True


class MissionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    client: str | None = None
    targets: list[str] = Field(default_factory=list)
    scope_rules: list[ScopeRuleIn] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=lambda: ["passive", "active"])
    parameters: dict[str, Any] = Field(default_factory=dict)
    authorization_token: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class MissionUpdate(BaseModel):
    name: str | None = None
    client: str | None = None
    targets: list[str] | None = None
    scope_rules: list[ScopeRuleIn] | None = None
    allowed_actions: list[str] | None = None
    parameters: dict[str, Any] | None = None
    authorization_token: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class MissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    client: str | None
    status: str
    targets: list[str]
    scope_rules: list[dict[str, Any]]
    allowed_actions: list[str]
    parameters: dict[str, Any]
    starts_at: datetime | None
    ends_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    mission_id: str
    module: str
    target: str
    title: str
    description: str
    severity: str
    evidence: dict[str, Any]
    references: list[str]
    discovered_at: datetime


class MissionRunRequest(BaseModel):
    modules: list[str] = Field(default_factory=lambda: ["recon", "webbreacher"])
    scenario: str | None = Field(
        default=None,
        description="ThreatSim scenario name; when set, overrides `modules`.",
    )


class MissionRunResponse(BaseModel):
    mission_id: str
    task_id: str
    status: str = "queued"

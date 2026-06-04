"""SQLAlchemy models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class MissionStatus(str, Enum):
    DRAFT = "draft"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="operator")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Mission(Base):
    __tablename__ = "missions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), index=True)
    client: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[MissionStatus] = mapped_column(
        SAEnum(
            MissionStatus,
            name="mission_status",
            # Store enum .value (lowercase) to match the DB type, not the
            # member NAME which SQLAlchemy uses by default.
            values_callable=lambda e: [m.value for m in e],
        ),
        default=MissionStatus.DRAFT,
        index=True,
    )
    targets: Mapped[list] = mapped_column(JSON, default=list)
    scope_rules: Mapped[list] = mapped_column(JSON, default=list)
    allowed_actions: Mapped[list] = mapped_column(
        JSON, default=lambda: ["passive", "active"]
    )
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    authorization_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    starts_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ends_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    findings: Mapped[list[Finding]] = relationship(
        back_populates="mission", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_mission_severity", "mission_id", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    mission_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("missions.id", ondelete="CASCADE"), index=True
    )
    module: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(
        SAEnum(
            Severity,
            name="finding_severity",
            values_callable=lambda e: [m.value for m in e],
        ),
        default=Severity.INFO,
    )
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    references: Mapped[list] = mapped_column(JSON, default=list)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

    mission: Mapped[Mission] = relationship(back_populates="findings")


class PhishClick(Base):
    """Click event recorded by the SocialMatrix tracking endpoint.

    No PII is stored - the recipient identity is hashed in the consent ledger,
    and the click row only carries the opaque token, timestamps and minimal
    request metadata for forensic correlation.
    """

    __tablename__ = "phish_clicks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    campaign_id: Mapped[str] = mapped_column(String(64), index=True)
    token: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    clicked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

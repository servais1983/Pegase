"""initial schema

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Each enum type is used by exactly one table, so we let the corresponding
# CREATE TABLE own its lifecycle (create_type defaults to True). We do NOT
# pre-create them, which avoids the "type already exists" telescoping between an
# explicit .create() and the implicit create during create_table.
mission_status = sa.Enum(
    "draft",
    "authorized",
    "running",
    "completed",
    "failed",
    "cancelled",
    name="mission_status",
)
finding_severity = sa.Enum(
    "info", "low", "medium", "high", "critical", name="finding_severity"
)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="operator"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "missions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("client", sa.String(length=255), nullable=True),
        sa.Column("status", mission_status, nullable=False, server_default="draft"),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("scope_rules", sa.JSON(), nullable=False),
        sa.Column("allowed_actions", sa.JSON(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("authorization_token", sa.Text(), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by",
            sa.String(length=36),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_missions_name", "missions", ["name"])
    op.create_index("ix_missions_status", "missions", ["status"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "mission_id",
            sa.String(length=36),
            sa.ForeignKey("missions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("module", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", finding_severity, nullable=False, server_default="info"),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_mission_id", "findings", ["mission_id"])
    op.create_index("ix_findings_module", "findings", ["module"])
    op.create_index("ix_findings_target", "findings", ["target"])
    op.create_index(
        "ix_findings_mission_severity", "findings", ["mission_id", "severity"]
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("missions")
    op.drop_table("users")
    finding_severity.drop(op.get_bind(), checkfirst=True)
    mission_status.drop(op.get_bind(), checkfirst=True)

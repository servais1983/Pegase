"""phish clicks table

Revision ID: 0002
Revises: 0001
Create Date: 2025-01-02 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "phish_clicks",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("campaign_id", sa.String(length=64), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False, unique=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("clicked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_phish_clicks_campaign_id", "phish_clicks", ["campaign_id"])
    op.create_index("ix_phish_clicks_token", "phish_clicks", ["token"], unique=True)


def downgrade() -> None:
    op.drop_table("phish_clicks")

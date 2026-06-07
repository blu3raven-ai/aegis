"""add posture_snapshots table

Revision ID: v6w7x8y9z0a1
Revises: u5v6w7x8y9z0
Create Date: 2026-06-04

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v6w7x8y9z0a1"
down_revision = "u5v6w7x8y9z0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "posture_snapshots",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("org", sa.String(255), nullable=False),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    # One snapshot per org per calendar day (UTC). snapshot_at is always stored
    # as midnight UTC so (org, snapshot_at) is naturally unique per day.
    op.create_index(
        "uq_posture_snapshots_org_day",
        "posture_snapshots",
        ["org", "snapshot_at"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_posture_snapshots_org_day", table_name="posture_snapshots")
    op.drop_table("posture_snapshots")

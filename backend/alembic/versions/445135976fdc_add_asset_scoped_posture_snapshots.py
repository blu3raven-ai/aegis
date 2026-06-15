"""add asset scoped posture snapshots

Revision ID: 445135976fdc
Revises: 5dc205191450
Create Date: 2026-06-14 23:49:27.878652

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "445135976fdc"
down_revision = "5dc205191450"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "posture_snapshots",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.dialects.postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("severity_critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity_high", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity_medium", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity_low", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("asset_id", "snapshot_date", name="uq_posture_snapshot_asset_date"),
    )
    op.create_index(
        "ix_posture_snapshots_date",
        "posture_snapshots",
        ["snapshot_date"],
    )
    op.create_index(
        "ix_posture_snapshots_asset",
        "posture_snapshots",
        ["asset_id"],
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

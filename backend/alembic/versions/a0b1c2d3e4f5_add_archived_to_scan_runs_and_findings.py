"""add archived to scan_runs and findings

Revision ID: a0b1c2d3e4f5
Revises: z0a1b2c3d4e5
Create Date: 2026-06-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "a0b1c2d3e4f5"
down_revision = "z0a1b2c3d4e5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "scan_runs",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_runs",
        sa.Column("archived_by_rule_id", sa.String(64), nullable=True),
    )
    op.create_index("ix_scanrun_archived", "scan_runs", ["archived"])

    op.add_column(
        "findings",
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "findings",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("archived_by_rule_id", sa.String(64), nullable=True),
    )
    op.create_index("ix_findings_archived", "findings", ["archived"])


def downgrade() -> None:
    op.drop_index("ix_findings_archived", table_name="findings")
    op.drop_column("findings", "archived_by_rule_id")
    op.drop_column("findings", "archived_at")
    op.drop_column("findings", "archived")
    op.drop_index("ix_scanrun_archived", table_name="scan_runs")
    op.drop_column("scan_runs", "archived_by_rule_id")
    op.drop_column("scan_runs", "archived_at")
    op.drop_column("scan_runs", "archived")

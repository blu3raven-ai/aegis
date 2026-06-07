"""add dry-run gate columns and rule_kill_switches table for auto-dismiss guardrails

Revision ID: z9a0b1c2d3e4
Revises: z0a1b2c3d4e5
Create Date: 2026-06-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "z9a0b1c2d3e4"
down_revision = "z0a1b2c3d4e5"


def upgrade() -> None:
    op.add_column("rules", sa.Column("last_dry_run_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("rules", sa.Column("last_dry_run_match_count", sa.Integer(), nullable=True))
    op.add_column("rules", sa.Column("dry_run_confirmation_token", sa.String(64), nullable=True))
    op.add_column("rules", sa.Column("dry_run_confirmed_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "rule_kill_switches",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(255), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("killed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("killed_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.UniqueConstraint("org_id", "category", name="uq_kill_switch_org_category"),
    )


def downgrade() -> None:
    op.drop_table("rule_kill_switches")
    op.drop_column("rules", "dry_run_confirmed_at")
    op.drop_column("rules", "dry_run_confirmation_token")
    op.drop_column("rules", "last_dry_run_match_count")
    op.drop_column("rules", "last_dry_run_at")

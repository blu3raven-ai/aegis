"""add scheduled reports table

Revision ID: b05903d2c795
Revises: 445135976fdc
Create Date: 2026-06-15 00:06:51.507532

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "b05903d2c795"
down_revision = "445135976fdc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scheduled_reports",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("report_type", sa.String(32), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("schedule_type", sa.String(16), nullable=False),
        sa.Column("schedule_value", sa.String(64), nullable=False),
        sa.Column(
            "filters",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "destination_ids",
            sa.dialects.postgresql.ARRAY(sa.BigInteger()),
            nullable=False,
            server_default=sa.text("'{}'::bigint[]"),
        ),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_status", sa.String(16), nullable=True),
        sa.Column("last_run_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "report_type IN ('findings', 'posture')",
            name="ck_scheduled_reports_type",
        ),
        sa.CheckConstraint(
            "format IN ('pdf', 'csv', 'json')",
            name="ck_scheduled_reports_format",
        ),
        sa.CheckConstraint(
            "schedule_type IN ('simple', 'cron')",
            name="ck_scheduled_reports_schedule_type",
        ),
        sa.CheckConstraint(
            "last_run_status IS NULL OR last_run_status IN ('success', 'failed')",
            name="ck_scheduled_reports_last_run_status",
        ),
    )
    op.create_index(
        "ix_scheduled_reports_enabled",
        "scheduled_reports",
        ["enabled"],
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

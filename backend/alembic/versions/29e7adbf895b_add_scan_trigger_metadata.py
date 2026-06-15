"""add scan trigger metadata

Revision ID: 29e7adbf895b
Revises: 593038952b6d
Create Date: 2026-06-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "29e7adbf895b"
down_revision = "593038952b6d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # scan_runs: trigger metadata
    op.add_column("scan_runs", sa.Column("triggered_by", sa.String(length=20), nullable=True))
    op.add_column("scan_runs", sa.Column("commit_sha", sa.String(length=64), nullable=True))
    op.add_column("scan_runs", sa.Column("branch", sa.String(length=255), nullable=True))
    op.add_column("scan_runs", sa.Column("pr_number", sa.Integer(), nullable=True))
    op.add_column("scan_runs", sa.Column("feedback_status", sa.String(length=20), nullable=False, server_default="not_applicable"))
    op.add_column("scan_runs", sa.Column("cancelled_reason", sa.String(length=64), nullable=True))
    op.add_column("scan_runs", sa.Column("failed_scanners", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("scan_runs", sa.Column("trigger_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_check_constraint(
        "ck_scan_runs_triggered_by",
        "scan_runs",
        "triggered_by IS NULL OR triggered_by IN ('scheduled','manual','webhook','ci','api')",
    )
    op.create_check_constraint(
        "ck_scan_runs_feedback_status",
        "scan_runs",
        "feedback_status IN ('not_applicable','pending','posted','failed','skipped')",
    )
    op.create_index("ix_scan_runs_pr_number", "scan_runs", ["pr_number"], unique=False)
    op.create_index("ix_scan_runs_feedback_status", "scan_runs", ["feedback_status"], unique=False)

    # Re-apply scan_runs status check constraint without semantic change so the
    # constraint text in the database stays byte-equal to the model declaration.
    op.drop_constraint("ck_scan_runs_status", "scan_runs", type_="check")
    op.create_check_constraint(
        "ck_scan_runs_status",
        "scan_runs",
        "status IN ('queued', 'running', 'ingesting', 'completed', 'completed_with_merge_error', 'failed', 'cancelled')",
    )

    # api_keys: per-source scoping
    op.add_column("api_keys", sa.Column("allowed_source_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""add missing check constraints to pre-existing tables

Revision ID: a1c3e8f2d94b
Revises: 2be1d26b5f3b
Create Date: 2026-07-07

The initial schema created the core tables without their CHECK constraints.
The v2 diff only added columns to existing tables without backfilling the
constraints. This migration adds the missing domain checks so the DB enforces
the same invariants the ORM models define.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "a1c3e8f2d94b"
down_revision: Union[str, Sequence[str], None] = "2be1d26b5f3b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # findings
    op.create_check_constraint(
        "ck_findings_state",
        "findings",
        "state IN ('open', 'deferred', 'dismissed', 'fixed')",
    )
    op.create_check_constraint(
        "ck_findings_verdict",
        "findings",
        "verdict IS NULL OR verdict IN ('confirmed','needs_verify','possible','ruled_out')",
    )
    op.create_check_constraint(
        "ck_findings_engine",
        "findings",
        "engine IS NULL OR engine IN ('semgrep', 'byo')",
    )
    op.create_check_constraint(
        "ck_findings_risk_score_range",
        "findings",
        "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
    )

    # scan_runs
    op.create_check_constraint(
        "ck_scan_runs_status",
        "scan_runs",
        "status IN ('queued', 'running', 'ingesting', 'completed', 'completed_with_merge_error', 'failed', 'cancelled')",
    )
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

    # source_connections
    op.create_check_constraint(
        "ck_source_connections_status",
        "source_connections",
        "status IN ('connected', 'syncing', 'error', 'disconnected', 'not-synced')",
    )
    op.create_check_constraint(
        "ck_source_connections_scan_scope",
        "source_connections",
        "scan_scope IN ('all', 'all-except-excluded')",
    )
    op.create_check_constraint(
        "ck_source_connections_sync_schedule",
        "source_connections",
        "sync_schedule IN ('1h', '3h', '6h', '12h', '24h')",
    )
    op.create_check_constraint(
        "ck_source_connections_scan_schedule_preset",
        "source_connections",
        "scan_schedule_preset IN ('1h', '3h', '6h', '12h', '24h')",
    )
    op.create_check_constraint(
        "ck_source_connections_sync_schedule_mode",
        "source_connections",
        "sync_schedule_mode IN ('preset', 'cron')",
    )
    op.create_check_constraint(
        "ck_source_connections_scan_schedule_mode",
        "source_connections",
        "scan_schedule_mode IN ('preset', 'cron')",
    )

    # runners
    op.create_check_constraint(
        "ck_runners_status",
        "runners",
        "status IN ('pending', 'pending_approval', 'approved')",
    )

    # runner_tokens
    op.create_check_constraint(
        "ck_runner_tokens_status",
        "runner_tokens",
        "status IN ('pending', 'used')",
    )

    # runner_jobs
    op.create_check_constraint(
        "ck_runner_jobs_status",
        "runner_jobs",
        "status IN ('pending', 'queued', 'assigned', 'running', 'completed', 'failed', 'cancelled')",
    )

    # notifications
    op.create_check_constraint(
        "ck_notifications_severity",
        "notifications",
        "severity IN ('critical', 'warning', 'success', 'error', 'info')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

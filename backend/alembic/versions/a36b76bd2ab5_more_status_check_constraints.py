"""add CHECK constraints to six more stringly-typed enum columns

Same defense as 75498c675f46 — encode the writer universe so an unknown
value fails fast at insert instead of silently sitting in the table.
Writer enumeration traced through state-machine transitions, hooks, and
default fallbacks (e.g. `RunnerJob.status = "pending"` from the
`job.get("status", "pending")` default at src/runner/storage.py:148).

Revision ID: a36b76bd2ab5
Revises: t6u7v8w9x0y1
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op

revision = "a36b76bd2ab5"
down_revision = "t6u7v8w9x0y1"


def upgrade() -> None:
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
        "ck_runner_tokens_status",
        "runner_tokens",
        "status IN ('pending', 'used')",
    )
    op.create_check_constraint(
        "ck_runner_jobs_status",
        "runner_jobs",
        "status IN ('pending', 'queued', 'assigned', 'running', 'completed', 'failed', 'cancelled')",
    )
    op.create_check_constraint(
        "ck_notif_deliveries_status",
        "notification_deliveries",
        "status IN ('delivered', 'failed')",
    )
    op.create_check_constraint(
        "ck_webhook_signing_secrets_status",
        "webhook_signing_secrets",
        "status IN ('active', 'rotating', 'revoked')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

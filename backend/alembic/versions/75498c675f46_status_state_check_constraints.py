"""lock down stringly-typed status/state columns with CHECK constraints

Each constraint encodes the exact value universe found in the writers — see
src/db/models.py for the same lists declared on the SQLAlchemy classes.

Revision ID: 75498c675f46
Revises: d7ac13b64466
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op

revision = "75498c675f46"
down_revision = "d7ac13b64466"


def upgrade() -> None:
    op.create_check_constraint(
        "ck_findings_state",
        "findings",
        "state IN ('open', 'dismissed', 'fixed')",
    )
    op.create_check_constraint(
        "ck_scan_runs_status",
        "scan_runs",
        "status IN ('queued', 'running', 'ingesting', 'completed', 'failed', 'cancelled')",
    )
    op.create_check_constraint(
        "ck_source_connections_status",
        "source_connections",
        "status IN ('connected', 'syncing', 'error', 'disconnected', 'not-synced')",
    )
    op.create_check_constraint(
        "ck_runners_status",
        "runners",
        "status IN ('pending', 'pending_approval', 'approved')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

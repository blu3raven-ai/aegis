"""widen status/state CHECK constraints to cover values missed in 75498c675f46

Two writer-set values were left out of the original constraints and would
have crashed real code paths the moment they were exercised:

- findings.state lacks 'deferred', emitted by dependencies/lifecycle.py:28
  and containers/lifecycle.py:25 as the initial state when no fix exists.
- scan_runs.status lacks 'completed_with_merge_error', a terminal state in
  the secrets-scanner state machine (src/secrets/scanner.py:567).

Revision ID: e7dfd6e839c9
Revises: 75498c675f46
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op

revision = "e7dfd6e839c9"
down_revision = "75498c675f46"


def upgrade() -> None:
    op.drop_constraint("ck_findings_state", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_state",
        "findings",
        "state IN ('open', 'deferred', 'dismissed', 'fixed')",
    )

    op.drop_constraint("ck_scan_runs_status", "scan_runs", type_="check")
    op.create_check_constraint(
        "ck_scan_runs_status",
        "scan_runs",
        "status IN ('queued', 'running', 'ingesting', 'completed', "
        "'completed_with_merge_error', 'failed', 'cancelled')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

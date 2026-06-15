"""add CHECK constraints to notifications.severity and reports.status

Both columns have a small, closed writer universe (severity is a
taxonomic enum, report status is a 3-state machine) so locking them in
is low-risk. Intentionally NOT constraining notifications.type or
notifications.category — those are open-ended event strings that grow
as new features land, and freezing them would crash the next feature
that adds a new notification kind.

Revision ID: 713b432e0824
Revises: u7v8w9x0y1z2
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op

revision = "713b432e0824"
down_revision = "u7v8w9x0y1z2"


def upgrade() -> None:
    op.create_check_constraint(
        "ck_notifications_severity",
        "notifications",
        "severity IN ('critical', 'warning', 'success', 'error', 'info')",
    )
    op.create_check_constraint(
        "ck_reports_status",
        "reports",
        "status IN ('pending', 'completed', 'failed')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

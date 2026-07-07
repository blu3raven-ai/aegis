"""backfill agent engine value to null

Revision ID: 2be1d26b5f3b
Revises: a1c3e8f2d94b
Create Date: 2026-07-08

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "2be1d26b5f3b"
down_revision = "bef98ef7bec2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The ck_findings_engine constraint (added in a1c3e8f2d94b) only allows
    # NULL, 'semgrep', or 'byo'. The agent_scanning lifecycle was writing
    # 'agent' as a fallback, which was never a documented engine value —
    # non-SAST tools (IaC, checkov) should use NULL per the model spec.
    # Backfill existing rows before the constraint is applied on any instance
    # that has not yet run a1c3e8f2d94b.
    op.execute(
        sa.text("UPDATE findings SET engine = NULL WHERE engine = 'agent'")
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

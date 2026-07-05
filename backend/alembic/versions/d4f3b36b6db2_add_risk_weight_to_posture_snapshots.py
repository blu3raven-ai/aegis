"""add risk_weight to posture_snapshots

Stores the exploitability-weighted raw volume (pre-gauge) per asset/day so the
posture trend can reflect KEV/reachability weighting, not just severity counts.
Existing rows are backfilled with the plain severity weighted volume — the
absence-neutral value (no historical KEV signal), matching how the gauge treated
them before.

Revision ID: d4f3b36b6db2
Revises: f491f1a9e9f9
"""
from alembic import op
import sqlalchemy as sa

revision = "d4f3b36b6db2"
down_revision = "f491f1a9e9f9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "posture_snapshots",
        sa.Column("risk_weight", sa.Integer(), nullable=False, server_default="0"),
    )
    # Backfill: severity weighted volume (critical*10 + high*5 + medium*2 + low).
    op.execute(
        """
        UPDATE posture_snapshots
        SET risk_weight = severity_critical * 10
                        + severity_high * 5
                        + severity_medium * 2
                        + severity_low
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

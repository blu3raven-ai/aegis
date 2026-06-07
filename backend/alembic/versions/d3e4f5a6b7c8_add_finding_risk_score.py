"""Add nullable risk_score column to findings.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-06-06
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("risk_score", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "ck_findings_risk_score_range",
        "findings",
        "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_findings_risk_score_range", "findings", type_="check")
    op.drop_column("findings", "risk_score")

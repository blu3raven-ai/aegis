"""add engine column to findings

Revision ID: m7n8o9p0q1r2
Revises: k5l6m7n8o9p0
Create Date: 2026-06-02 00:00:00.000000

Tags each finding with the engine that produced it. Currently only used
by SAST (code_scanning) to distinguish opengrep / joern / both. Other
tools leave engine NULL.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "m7n8o9p0q1r2"
down_revision: Union[str, Sequence[str], None] = "k5l6m7n8o9p0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("engine", sa.String(length=20), nullable=True),
    )
    op.execute(
        "UPDATE findings SET engine = 'opengrep' "
        "WHERE tool = 'code_scanning' AND engine IS NULL"
    )


def downgrade() -> None:
    op.drop_column("findings", "engine")

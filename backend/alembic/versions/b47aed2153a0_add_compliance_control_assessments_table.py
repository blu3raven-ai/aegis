"""add compliance control assessments table

Revision ID: b47aed2153a0
Revises: 87a45499d328
Create Date: 2026-06-27 18:28:24.927806

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b47aed2153a0'
down_revision: Union[str, Sequence[str], None] = '87a45499d328'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_control_assessments",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("framework", sa.String(length=64), nullable=False),
        sa.Column("control_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=True),
        sa.Column("evidence_note", sa.Text(), nullable=True),
        sa.Column("evidence_url", sa.String(length=1024), nullable=True),
        sa.Column("assessed_by_user_id", sa.String(length=255), nullable=True),
        sa.Column("assessed_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("framework", "control_id", name="uq_control_assessment"),
    )
    op.create_index(
        "ix_control_assessments_fw", "compliance_control_assessments", ["framework"]
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

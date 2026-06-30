"""add suppression to compliance control mappings

Revision ID: 8f227f22220a
Revises: b47aed2153a0
Create Date: 2026-06-27 19:02:25.566054

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f227f22220a'
down_revision: Union[str, Sequence[str], None] = 'b47aed2153a0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_control_mappings",
        sa.Column("suppressed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("compliance_control_mappings", sa.Column("suppressed_reason", sa.Text(), nullable=True))
    op.add_column("compliance_control_mappings", sa.Column("suppressed_by_user_id", sa.String(length=255), nullable=True))
    op.add_column("compliance_control_mappings", sa.Column("suppressed_at", sa.TIMESTAMP(timezone=True), nullable=True))


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

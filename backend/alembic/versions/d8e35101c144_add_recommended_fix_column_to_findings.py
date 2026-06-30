"""add recommended_fix column to findings

Revision ID: d8e35101c144
Revises: e9a1c7d54f08
Create Date: 2026-06-28 20:06:14.750001

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'd8e35101c144'
down_revision: Union[str, Sequence[str], None] = 'e9a1c7d54f08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add a typed recommended_fix payload promoted from `detail` at ingest, so
    runner-emitted remediations for secrets/IaC/SAST aren't buried in the fat
    detail blob. Existing rows backfill on the asset's next scan."""
    op.add_column(
        'findings',
        sa.Column('recommended_fix', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

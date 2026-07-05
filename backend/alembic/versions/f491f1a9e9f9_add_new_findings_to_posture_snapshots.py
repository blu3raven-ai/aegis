"""add new_findings to posture_snapshots

Revision ID: f491f1a9e9f9
Revises: 88f583b1c73a
Create Date: 2026-07-01 17:55:14.677199

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f491f1a9e9f9'
down_revision: Union[str, Sequence[str], None] = '88f583b1c73a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('posture_snapshots', sa.Column(
        'new_findings', sa.Integer(), nullable=False, server_default='0',
    ))


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

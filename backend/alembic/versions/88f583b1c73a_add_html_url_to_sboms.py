"""add html_url to sboms

Revision ID: 88f583b1c73a
Revises: 182abf277f9d
Create Date: 2026-07-01 11:18:14.701894

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '88f583b1c73a'
down_revision: Union[str, Sequence[str], None] = '182abf277f9d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the repo web URL column to sboms (deep-links deps findings)."""
    op.add_column("sboms", sa.Column("html_url", sa.String(length=1024), nullable=True))


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

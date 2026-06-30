"""add declared_range to sbom_components

Revision ID: a5a367eabcee
Revises: 5e3e0c4f74c9
Create Date: 2026-06-29 21:27:48.611043

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a5a367eabcee'
down_revision: Union[str, Sequence[str], None] = '5e3e0c4f74c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("sbom_components", sa.Column("declared_range", sa.String(length=256), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    raise NotImplementedError("Forward-only; no downgrade.")

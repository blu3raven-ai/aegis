"""add sbom component manifest location columns

Revision ID: 182abf277f9d
Revises: c4e9b1f7a3d2
Create Date: 2026-07-01 09:28:13.709861

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '182abf277f9d'
down_revision: Union[str, Sequence[str], None] = 'c4e9b1f7a3d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add manifest location + code-window columns to sbom_components."""
    op.add_column("sbom_components", sa.Column("manifest_path", sa.String(length=1024), nullable=True))
    op.add_column("sbom_components", sa.Column("manifest_line", sa.Integer(), nullable=True))
    op.add_column("sbom_components", sa.Column("manifest_snippet", sa.Text(), nullable=True))
    op.add_column("sbom_components", sa.Column("manifest_snippet_start", sa.Integer(), nullable=True))


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

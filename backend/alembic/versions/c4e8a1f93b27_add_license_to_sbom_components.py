"""add license to sbom_components

Revision ID: c4e8a1f93b27
Revises: b1d4e7a92c3f
Create Date: 2026-06-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4e8a1f93b27'
down_revision: Union[str, Sequence[str], None] = 'b1d4e7a92c3f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the normalized license display string + computed risk category to
    sbom_components, with an index to back the estate-wide license-category
    facet/filter. Both nullable — legacy and license-less rows have none, and
    the columns self-backfill on the asset's next scan (delete+insert ingest)."""
    op.add_column('sbom_components', sa.Column('license_expression', sa.String(length=512), nullable=True))
    op.add_column('sbom_components', sa.Column('license_category', sa.String(length=32), nullable=True))
    op.create_index(
        'idx_sbom_components_asset_license_cat', 'sbom_components',
        ['asset_id', 'license_category'], unique=False,
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

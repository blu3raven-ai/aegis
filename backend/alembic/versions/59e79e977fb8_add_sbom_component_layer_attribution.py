"""add sbom_components layer attribution

Revision ID: 59e79e977fb8
Revises: 40b8cafd7049
Create Date: 2026-07-04 21:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "59e79e977fb8"
down_revision: Union[str, Sequence[str], None] = "40b8cafd7049"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the introducing-image-layer digest + ordinal to SBOM components.

    Both nullable — repo components and OS packages with no attributable layer
    carry null, and the next container scan backfills them.
    """
    op.add_column(
        "sbom_components",
        sa.Column("layer_digest", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "sbom_components",
        sa.Column("layer_index", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

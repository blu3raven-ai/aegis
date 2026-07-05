"""add sbom_components.scope

Revision ID: 40b8cafd7049
Revises: edc0ec32100b
Create Date: 2026-07-04 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "40b8cafd7049"
down_revision: Union[str, Sequence[str], None] = "edc0ec32100b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add per-direct-dependency scope ("dev"/"prod") to SBOM components.

    Nullable — transitive deps and SBOMs indexed before this column existed
    carry no scope, so the next scan backfills it for direct deps.
    """
    op.add_column(
        "sbom_components",
        sa.Column("scope", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

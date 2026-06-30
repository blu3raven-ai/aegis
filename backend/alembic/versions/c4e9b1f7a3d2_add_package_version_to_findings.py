"""add package_version to findings

Revision ID: c4e9b1f7a3d2
Revises: a5a367eabcee
Create Date: 2026-06-30 11:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4e9b1f7a3d2'
down_revision: Union[str, Sequence[str], None] = 'a5a367eabcee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("findings", sa.Column("package_version", sa.String(length=256), nullable=True))
    # Backfill from the detail JSONB. currentVersion is the SCA/container shape
    # written today; the others cover any legacy/alternate adapter rows. Only
    # touch package-bearing rows that don't already have a version.
    op.execute(
        """
        UPDATE findings
        SET package_version = COALESCE(
            NULLIF(detail->>'currentVersion', ''),
            NULLIF(detail->>'current_version', ''),
            NULLIF(detail->>'packageVersion', ''),
            NULLIF(detail->>'package_version', '')
        )
        WHERE package_version IS NULL
          AND package_name IS NOT NULL
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    raise NotImplementedError("Forward-only; no downgrade.")

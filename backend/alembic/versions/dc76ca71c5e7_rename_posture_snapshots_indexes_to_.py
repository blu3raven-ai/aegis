"""rename posture_snapshots indexes to match models

Revision ID: dc76ca71c5e7
Revises: 8e502a0c02b7
Create Date: 2026-06-28 13:36:48.274015

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dc76ca71c5e7'
down_revision: Union[str, Sequence[str], None] = '8e502a0c02b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Rename the posture_snapshots indexes to the names SQLAlchemy derives from
    the model's bare ``index=True`` columns, so autogenerate stops emitting
    spurious drop/create ops for them."""
    op.execute(
        "ALTER INDEX ix_posture_snapshots_asset "
        "RENAME TO ix_posture_snapshots_asset_id"
    )
    op.execute(
        "ALTER INDEX ix_posture_snapshots_date "
        "RENAME TO ix_posture_snapshots_snapshot_date"
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

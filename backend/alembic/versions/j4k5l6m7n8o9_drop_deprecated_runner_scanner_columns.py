"""drop deprecated scanner_images and active_containers columns from runners

Revision ID: j4k5l6m7n8o9
Revises: i8j9k0l1m2n3
Create Date: 2026-06-01 00:00:00.000000

Both columns were vestiges of the Docker-spawn scanner model. PR #166
(embedded-scanners migration) stopped reading and writing them. This
migration removes them from the schema.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "j4k5l6m7n8o9"
down_revision: Union[str, Sequence[str], None] = "i8j9k0l1m2n3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("runners", "scanner_images")
    op.drop_column("runners", "active_containers")


def downgrade() -> None:
    op.add_column("runners", sa.Column("active_containers", JSONB(), nullable=True))
    op.add_column("runners", sa.Column("scanner_images", JSONB(), nullable=True))

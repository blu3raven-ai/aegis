"""add package_release_dates cache

Revision ID: 94927735cbeb
Revises: 59e79e977fb8
Create Date: 2026-07-04 22:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "94927735cbeb"
down_revision: Union[str, Sequence[str], None] = "59e79e977fb8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Cache table for deps.dev package-version publish dates.

    Populated lazily by the opt-in release-age enrichment; keyed by deps.dev
    system + package name + version. ``published_at`` may be null (a cached
    "deps.dev has no date" miss).
    """
    op.create_table(
        "package_release_dates",
        sa.Column("system", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("version", sa.String(length=256), nullable=False),
        sa.Column("published_at", sa.Date(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("system", "name", "version"),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""add scanners column to source_connections

Revision ID: c3f1a7e92b04
Revises: 5bb8a3bc6cbd
Create Date: 2026-06-21 02:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "c3f1a7e92b04"
down_revision: Union[str, Sequence[str], None] = "5bb8a3bc6cbd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "source_connections",
        sa.Column(
            "scanners",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

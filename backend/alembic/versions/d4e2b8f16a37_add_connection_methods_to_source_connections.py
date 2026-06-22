"""add connection_methods column to source_connections

Revision ID: d4e2b8f16a37
Revises: c3f1a7e92b04
Create Date: 2026-06-21 02:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "d4e2b8f16a37"
down_revision: Union[str, Sequence[str], None] = "c3f1a7e92b04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "source_connections",
        sa.Column(
            "connection_methods",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default='["pat"]',
        ),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

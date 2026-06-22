"""add scim_managed flag to users

Revision ID: 3cb39a73c326
Revises: 707b792c0813
Create Date: 2026-06-16 09:42:30.535482

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3cb39a73c326'
down_revision: Union[str, Sequence[str], None] = '707b792c0813'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "users",
        sa.Column(
            "scim_managed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    raise NotImplementedError("Forward-only; no downgrade.")

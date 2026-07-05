"""consolidate all post-initial-schema migrations

Revision ID: 4f891e8375be
Revises: 9de8c6a3b86f
Create Date: 2026-07-05 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4f891e8375be"
down_revision: Union[str, Sequence[str], None] = "9de8c6a3b86f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

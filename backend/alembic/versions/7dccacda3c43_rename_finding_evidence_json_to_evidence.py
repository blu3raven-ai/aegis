"""rename finding evidence_json to evidence

Revision ID: 7dccacda3c43
Revises: 3cb39a73c326
Create Date: 2026-06-16 12:00:03.743577

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '7dccacda3c43'
down_revision: Union[str, Sequence[str], None] = '3cb39a73c326'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column(
        "findings",
        "evidence_json",
        new_column_name="evidence",
    )


def downgrade() -> None:
    """Downgrade schema."""
    raise NotImplementedError("Forward-only; no downgrade.")

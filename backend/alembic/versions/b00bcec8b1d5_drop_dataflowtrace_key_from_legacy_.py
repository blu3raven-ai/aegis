"""drop dataflowTrace key from legacy finding rows

Revision ID: b00bcec8b1d5
Revises: da5a67c73e79
Create Date: 2026-06-15 20:03:00.452498

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'b00bcec8b1d5'
down_revision: Union[str, Sequence[str], None] = 'da5a67c73e79'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "UPDATE findings SET detail = detail - 'dataflowTrace' "
        "WHERE detail ? 'dataflowTrace'"
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

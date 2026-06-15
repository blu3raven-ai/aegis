"""normalize pre-joern engine rows

Revision ID: da5a67c73e79
Revises: a2fcb811435a
Create Date: 2026-06-15 19:41:49.152674

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'da5a67c73e79'
down_revision: Union[str, Sequence[str], None] = 'a2fcb811435a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "UPDATE findings SET engine = NULL "
        "WHERE engine IS NOT NULL AND engine NOT IN ('semgrep', 'byo')"
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""constrain finding engine to known values

Revision ID: a2fcb811435a
Revises: 41953bd5a8e8
Create Date: 2026-06-15 10:31:18.583190

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a2fcb811435a'
down_revision: Union[str, Sequence[str], None] = '41953bd5a8e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_findings_engine",
        "findings",
        "engine IS NULL OR engine IN ('semgrep', 'byo')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

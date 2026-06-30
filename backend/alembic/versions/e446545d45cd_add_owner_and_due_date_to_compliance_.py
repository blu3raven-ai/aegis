"""add owner and due_date to compliance control assessments

Revision ID: e446545d45cd
Revises: 8f227f22220a
Create Date: 2026-06-27 22:21:57.721974

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e446545d45cd'
down_revision: Union[str, Sequence[str], None] = '8f227f22220a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_control_assessments",
        sa.Column("owner_user_id", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "compliance_control_assessments",
        sa.Column("due_date", sa.Date(), nullable=True),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""user pending email verification

Revision ID: c4e19a7b2f83
Revises: b36d93a0cb9e
Create Date: 2026-07-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c4e19a7b2f83'
down_revision: Union[str, Sequence[str], None] = 'b36d93a0cb9e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('pending_email', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('pending_email_token_hash', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('pending_email_expires_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

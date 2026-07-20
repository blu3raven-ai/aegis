"""api key creator fk

Revision ID: e8a2c51f9d04
Revises: d7f3a1c9e42b
Create Date: 2026-07-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e8a2c51f9d04'
down_revision: Union[str, Sequence[str], None] = 'd7f3a1c9e42b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'api_keys',
        sa.Column('created_by_user_id', sa.String(length=255), nullable=True),
    )
    op.create_foreign_key(
        'api_keys_created_by_user_id_fkey',
        'api_keys',
        'users',
        ['created_by_user_id'],
        ['id'],
        ondelete='CASCADE',
    )
    # Best-effort backfill: link legacy keys to their creator by matching the
    # display string (created_by) against users.username. Rows that don't match
    # stay NULL and are governed only by the existing hash/expiry checks.
    op.execute(
        "UPDATE api_keys AS k "
        "SET created_by_user_id = u.id "
        "FROM users AS u "
        "WHERE k.created_by_user_id IS NULL AND k.created_by = u.username"
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""notification delivery retry fields

Revision ID: cf8b88a32db4
Revises: d4f3b36b6db2
Create Date: 2026-07-02 11:24:17.721421

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cf8b88a32db4'
down_revision: Union[str, Sequence[str], None] = 'd4f3b36b6db2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('notification_deliveries', sa.Column('attempts', sa.Integer(), server_default='1', nullable=False))
    op.add_column('notification_deliveries', sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('notification_deliveries', sa.Column('payload', sa.Text(), nullable=True))
    op.create_index('ix_notif_deliveries_retry', 'notification_deliveries', ['status', 'next_attempt_at'], unique=False)
    # Widen the status CHECK to admit the new 'retry' state. Alembic does not
    # autodetect CHECK-constraint edits, so this is done by hand.
    op.drop_constraint('ck_notif_deliveries_status', 'notification_deliveries', type_='check')
    op.create_check_constraint(
        'ck_notif_deliveries_status',
        'notification_deliveries',
        "status IN ('delivered', 'failed', 'retry')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

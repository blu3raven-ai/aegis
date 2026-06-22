"""constrain notification_destinations destination_type to (slack, webhook, email)

Revision ID: 707b792c0813
Revises: b00bcec8b1d5
Create Date: 2026-06-16 01:04:59.482095

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '707b792c0813'
down_revision: Union[str, Sequence[str], None] = 'b00bcec8b1d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_check_constraint(
        "ck_notification_destinations_destination_type",
        "notification_destinations",
        "destination_type IN ('slack', 'webhook', 'email')",
    )


def downgrade() -> None:
    """Downgrade schema."""
    raise NotImplementedError("Forward-only; no downgrade.")

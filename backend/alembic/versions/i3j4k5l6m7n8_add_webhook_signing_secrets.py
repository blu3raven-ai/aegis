"""add webhook_signing_secrets table for Phase 44 HMAC signing

Revision ID: i3j4k5l6m7n8
Revises: h2i3j4k5l6m7
Create Date: 2026-05-31 00:00:00.000000

Phase 44: per-channel signing secrets for outbound webhook HMAC-SHA256
authentication. Supports rotation — multiple active versions during the
handover window; receivers verify against all non-revoked secrets.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'i3j4k5l6m7n8'
down_revision: Union[str, Sequence[str], None] = 'h2i3j4k5l6m7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'webhook_signing_secrets',
        sa.Column('id', sa.String(64), nullable=False),
        sa.Column(
            'channel_id',
            sa.BigInteger(),
            sa.ForeignKey('notification_destinations.id', ondelete='CASCADE'),
            nullable=False,
        ),
        # SHA-256 hex digest of the raw secret — raw value is never persisted
        sa.Column('secret_hash', sa.String(64), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        # 'active' | 'rotating' | 'revoked'
        sa.Column('status', sa.String(20), nullable=False, server_default='active'),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text('NOW()'),
        ),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_wss_channel_id_status', 'webhook_signing_secrets', ['channel_id', 'status'])
    op.create_index('ix_wss_channel_id_version', 'webhook_signing_secrets', ['channel_id', 'version'])


def downgrade() -> None:
    op.drop_index('ix_wss_channel_id_version', table_name='webhook_signing_secrets')
    op.drop_index('ix_wss_channel_id_status', table_name='webhook_signing_secrets')
    op.drop_table('webhook_signing_secrets')

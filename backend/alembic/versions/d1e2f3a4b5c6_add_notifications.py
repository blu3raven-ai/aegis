"""add notification_destinations and notification_deliveries tables for Phase 13

Revision ID: d1e2f3a4b5c6
Revises: c5d6e7f8a9b0
Create Date: 2026-05-31 00:00:00.000000

Phase 13: external notification routing. Destinations hold per-org outbound
channel configs (Slack, generic webhook, email). Deliveries are the audit trail
of every dispatch attempt with status and error information for retries.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = 'd1e2f3a4b5c6'
down_revision: Union[str, Sequence[str], None] = 'c5d6e7f8a9b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'notification_destinations',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('org_id', sa.String(255), nullable=False),
        sa.Column('destination_type', sa.String(32), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('config', JSONB, nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('event_filter', JSONB, nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_id', 'name', name='uq_notif_dest_org_name'),
    )
    op.create_index('ix_notif_dest_org_id', 'notification_destinations', ['org_id'])

    op.create_table(
        'notification_deliveries',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('destination_id', sa.BigInteger(), nullable=False),
        sa.Column('event_id', sa.String(64), nullable=False),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('payload_summary', sa.Text(), nullable=True),
        sa.Column('response_code', sa.Integer(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('attempted_at', sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['destination_id'], ['notification_destinations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('destination_id', 'event_id', name='uq_notif_delivery_dest_event'),
    )
    op.create_index(
        'ix_notif_deliveries_status',
        'notification_deliveries',
        ['status', 'attempted_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_notif_deliveries_status', table_name='notification_deliveries')
    op.drop_table('notification_deliveries')
    op.drop_index('ix_notif_dest_org_id', table_name='notification_destinations')
    op.drop_table('notification_destinations')

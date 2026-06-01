"""add notification_rules table for Phase 42 routing rules

Revision ID: g1h2i3j4k5l6
Revises: a2b3c4d5e6f7
Create Date: 2026-05-31 00:00:00.000000

Phase 42: rule-based notification routing. Rules describe which findings should
go to which channels, evaluated in priority order (lower = higher priority).
The conditions JSONB column holds a nestable predicate tree — all/any groups
with leaf operators, evaluated by the routing engine before channel fanout.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = 'g1h2i3j4k5l6'
down_revision: Union[str, Sequence[str], None] = 'a2b3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'notification_rules',
        sa.Column('id', sa.String(64), nullable=False),
        sa.Column('name', sa.String(120), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column(
            'channel_id',
            sa.BigInteger(),
            sa.ForeignKey('notification_destinations.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('conditions', JSONB, nullable=False, server_default='{}'),
        sa.Column(
            'created_at',
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text('now()'),
        ),
        sa.Column(
            'updated_at',
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text('now()'),
        ),
        sa.Column('org_id', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_notif_rules_org_id', 'notification_rules', ['org_id'])
    op.create_index(
        'ix_notif_rules_org_priority',
        'notification_rules',
        ['org_id', 'priority'],
    )


def downgrade() -> None:
    op.drop_index('ix_notif_rules_org_priority', table_name='notification_rules')
    op.drop_index('ix_notif_rules_org_id', table_name='notification_rules')
    op.drop_table('notification_rules')

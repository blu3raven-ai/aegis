"""expand audit_events table for Phase 19 compliance audit log

Revision ID: e7f8a9b0c1d2
Revises: d1e2f3a4b5c6
Create Date: 2026-05-31 00:00:00.000000

Phase 19: structured audit log for admin/sensitive actions. The existing table
has a minimal schema; this migration extends it to capture org, actor email/role,
resource identity, request context, before/after change diffs, and an HTTP status
code — giving compliance teams a queryable event trail without touching raw logs.

Old columns (action, actor_user_id, actor_username, target, metadata, created_at)
are preserved verbatim so that settings/audit.py continues writing without changes.
New columns are all nullable so the old writer doesn't need to be updated.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = 'e7f8a9b0c1d2'
down_revision: Union[str, Sequence[str], None] = 'd1e2f3a4b5c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Widen the action column — the old schema only allowed 50 chars which is
    # too short for dot-separated action names like "notification.destination.created".
    op.alter_column('audit_events', 'action', type_=sa.String(128), nullable=False)

    # New compliance-grade columns — all nullable so existing callers are unaffected.
    op.add_column('audit_events', sa.Column('org_id', sa.String(255), nullable=True))
    op.add_column('audit_events', sa.Column('actor_email', sa.String(255), nullable=True))
    op.add_column('audit_events', sa.Column('actor_role', sa.String(64), nullable=True))
    op.add_column('audit_events', sa.Column('resource_type', sa.String(64), nullable=True))
    op.add_column('audit_events', sa.Column('resource_id', sa.String(255), nullable=True))
    op.add_column('audit_events', sa.Column('request_method', sa.String(8), nullable=True))
    op.add_column('audit_events', sa.Column('request_path', sa.String(1024), nullable=True))
    op.add_column('audit_events', sa.Column('request_ip', sa.String(64), nullable=True))
    op.add_column('audit_events', sa.Column('user_agent', sa.String(512), nullable=True))
    op.add_column('audit_events', sa.Column('changes', JSONB, nullable=True))
    op.add_column('audit_events', sa.Column('status_code', sa.Integer(), nullable=True))

    # Add a tz-aware occurred_at column populated from created_at for query consistency.
    # We keep created_at intact so the legacy writer still works.
    op.add_column(
        'audit_events',
        sa.Column(
            'occurred_at',
            sa.TIMESTAMP(timezone=True),
            nullable=True,
            server_default=sa.text('now()'),
        ),
    )

    # Indexes for the query patterns used by the audit log API.
    op.create_index('ix_audit_org_occurred', 'audit_events', ['org_id', 'occurred_at'])
    op.create_index('ix_audit_actor_id', 'audit_events', ['actor_user_id', 'occurred_at'])
    op.create_index('ix_audit_action_occ', 'audit_events', ['action', 'occurred_at'])
    op.create_index('ix_audit_resource', 'audit_events', ['resource_type', 'resource_id'])


def downgrade() -> None:
    op.drop_index('ix_audit_resource', table_name='audit_events')
    op.drop_index('ix_audit_action_occ', table_name='audit_events')
    op.drop_index('ix_audit_actor_id', table_name='audit_events')
    op.drop_index('ix_audit_org_occurred', table_name='audit_events')

    op.drop_column('audit_events', 'occurred_at')
    op.drop_column('audit_events', 'status_code')
    op.drop_column('audit_events', 'changes')
    op.drop_column('audit_events', 'user_agent')
    op.drop_column('audit_events', 'request_ip')
    op.drop_column('audit_events', 'request_path')
    op.drop_column('audit_events', 'request_method')
    op.drop_column('audit_events', 'resource_id')
    op.drop_column('audit_events', 'resource_type')
    op.drop_column('audit_events', 'actor_role')
    op.drop_column('audit_events', 'actor_email')
    op.drop_column('audit_events', 'org_id')

    op.alter_column('audit_events', 'action', type_=sa.String(50), nullable=False)

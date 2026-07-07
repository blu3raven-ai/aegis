"""add org_id to runner, source_connection, api_key, audit_event

Revision ID: bef98ef7bec2
Revises: 52e36215dd4a
Create Date: 2026-07-07

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'bef98ef7bec2'
down_revision: Union[str, Sequence[str], None] = '52e36215dd4a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'runners',
        sa.Column('org_id', sa.String(255), nullable=True),
    )
    op.add_column(
        'source_connections',
        sa.Column('org_id', sa.String(255), nullable=False, server_default='default'),
    )
    op.add_column(
        'api_keys',
        sa.Column('org_id', sa.String(255), nullable=False, server_default='default'),
    )
    op.add_column(
        'audit_events',
        sa.Column('org_id', sa.String(255), nullable=False, server_default='default'),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""add kev_entries table for CISA KEV catalog (Phase 48)

Revision ID: h7i8j9k0l1m2
Revises: g1h2i3j4k5l6
Create Date: 2026-05-31 00:00:00.000000

The kev_entries table mirrors the CISA Known Exploited Vulnerabilities catalog.
Rows are upserted on each daily refresh; cve_id is the natural PK because CISA
guarantees uniqueness and it's the join key used by findings queries.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = 'h7i8j9k0l1m2'
down_revision: Union[str, Sequence[str], None] = 'i3j4k5l6m7n8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'kev_entries',
        sa.Column('cve_id', sa.String(20), nullable=False),
        sa.Column('vendor_project', sa.String(120), nullable=True),
        sa.Column('product', sa.String(120), nullable=True),
        sa.Column('vulnerability_name', sa.String(255), nullable=True),
        sa.Column('date_added', sa.Date(), nullable=True),
        sa.Column('short_description', sa.Text(), nullable=True),
        sa.Column('required_action', sa.Text(), nullable=True),
        sa.Column('due_date', sa.Date(), nullable=True),
        sa.Column('known_ransomware_use', sa.Boolean(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('cwes', JSONB, nullable=True),
        sa.Column(
            'ingested_at',
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text('now()'),
        ),
        sa.PrimaryKeyConstraint('cve_id'),
    )
    op.create_index('ix_kev_entries_date_added', 'kev_entries', ['date_added'])


def downgrade() -> None:
    op.drop_index('ix_kev_entries_date_added', table_name='kev_entries')
    op.drop_table('kev_entries')

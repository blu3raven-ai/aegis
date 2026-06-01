"""add epss_scores table for FIRST.org EPSS scores (Phase 50)

Revision ID: i8j9k0l1m2n3
Revises: h7i8j9k0l1m2
Create Date: 2026-05-31 00:00:00.000000

The epss_scores table mirrors the latest EPSS feed from FIRST.org. Rows are
upserted on each daily refresh; cve is the natural PK because the feed
publishes one current row per CVE and findings join on it directly.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'i8j9k0l1m2n3'
down_revision: Union[str, Sequence[str], None] = 'h7i8j9k0l1m2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'epss_scores',
        sa.Column('cve', sa.String(20), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('percentile', sa.Float(), nullable=False),
        sa.Column('scored_date', sa.Date(), nullable=False),
        sa.Column(
            'fetched_at',
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text('now()'),
        ),
        sa.PrimaryKeyConstraint('cve'),
    )
    op.create_index('ix_epss_scores_scored_date', 'epss_scores', ['scored_date'])
    op.create_index('ix_epss_scores_score', 'epss_scores', ['score'])


def downgrade() -> None:
    op.drop_index('ix_epss_scores_score', table_name='epss_scores')
    op.drop_index('ix_epss_scores_scored_date', table_name='epss_scores')
    op.drop_table('epss_scores')

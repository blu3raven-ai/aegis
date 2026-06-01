"""add temporal_aggregates table for Phase 11 time-series correlation

Revision ID: c5d6e7f8a9b0
Revises: b3c4d5e6f7a8
Create Date: 2026-05-31 00:00:00.000000

Spec §5.6 Type 4: temporal/behavioral pattern storage. Bucketed aggregates allow
the correlation engine to answer questions like "how many findings did this author
introduce this week?" or "what is the MTTR for critical secrets findings?" without
full-table scans against the findings table. The unique constraint enforces one row
per (org, metric, dimension, bucket) so upserts are idempotent.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision: str = 'c5d6e7f8a9b0'
down_revision: Union[str, Sequence[str], None] = 'b3c4d5e6f7a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'temporal_aggregates',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('org_id', sa.String(255), nullable=False),
        # Identifies which metric this row tracks — e.g. 'findings_introduced',
        # 'findings_remediated', 'mttr'.
        sa.Column('metric_type', sa.String(64), nullable=False),
        # Composite dimension string for multi-key slicing without a separate
        # dimension table; format is "k1=v1|k2=v2" sorted by key for stable
        # deduplication across callers.
        sa.Column('dimension_key', sa.String(512), nullable=False),
        sa.Column('bucket_start', sa.DateTime(timezone=True), nullable=False),
        # '1h' | '1d' | '1w' — kept as a string so new granularities never
        # require a schema change.
        sa.Column('bucket_size', sa.String(16), nullable=False),
        sa.Column('value', sa.Float(), nullable=False),
        # Stores arbitrary extra context (e.g. raw duration samples for MTTR P50).
        sa.Column('metadata', JSONB, nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'org_id', 'metric_type', 'dimension_key', 'bucket_start', 'bucket_size',
            name='uq_temporal_aggregate_bucket',
        ),
    )
    # Hot path: list series for a given org + metric ordered by time desc.
    op.create_index(
        'ix_temporal_org_metric_bucket',
        'temporal_aggregates',
        ['org_id', 'metric_type', 'bucket_start'],
        postgresql_ops={'bucket_start': 'DESC NULLS LAST'},
    )


def downgrade() -> None:
    op.drop_index('ix_temporal_org_metric_bucket', table_name='temporal_aggregates')
    op.drop_table('temporal_aggregates')

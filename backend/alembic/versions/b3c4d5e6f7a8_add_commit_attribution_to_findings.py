"""add commit attribution columns to findings

Revision ID: b3c4d5e6f7a8
Revises: 876f112b2034
Create Date: 2026-05-31 00:00:00.000000

Spec §5.6: commit/PR attribution as a derived field on findings (v1 carve-out
from type 4 temporal correlation). Columns are additive, all nullable — no
backfill; existing rows keep NULL values and the scan pipeline still works
without a checkout.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b3c4d5e6f7a8'
down_revision: Union[str, Sequence[str], None] = '876f112b2034'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column(
        'introduced_by_commit_sha', sa.String(64), nullable=True
    ))
    op.add_column('findings', sa.Column(
        'introduced_by_author', sa.String(255), nullable=True
    ))
    op.add_column('findings', sa.Column(
        'introduced_at', sa.DateTime(timezone=True), nullable=True
    ))
    op.add_column('findings', sa.Column(
        'introduced_by_pr_url', sa.String(512), nullable=True
    ))


def downgrade() -> None:
    op.drop_column('findings', 'introduced_by_pr_url')
    op.drop_column('findings', 'introduced_at')
    op.drop_column('findings', 'introduced_by_author')
    op.drop_column('findings', 'introduced_by_commit_sha')

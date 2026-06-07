"""add detail_blob_key to findings

Revision ID: q1r2s3t4u5v6
Revises: p0q1r2s3t4u5
Create Date: 2026-06-02

"""
from __future__ import annotations

from alembic import op


revision = "q1r2s3t4u5v6"
down_revision = "p0q1r2s3t4u5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    import sqlalchemy as sa
    op.add_column(
        "findings",
        sa.Column("detail_blob_key", sa.String(length=512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "detail_blob_key")

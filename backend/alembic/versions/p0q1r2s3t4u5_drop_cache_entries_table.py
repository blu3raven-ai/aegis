"""drop cache_entries table

Revision ID: p0q1r2s3t4u5
Revises: o9p0q1r2s3t4
Create Date: 2026-06-02 00:00:00.000000

The table had no remaining writers (sbom_cache.py removed in SR2) or
readers (sbom router rewired to read from MinIO directly in SR1).
"""
from __future__ import annotations

from alembic import op


revision = "p0q1r2s3t4u5"
down_revision = "o9p0q1r2s3t4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_cache_entries_last_used_at", table_name="cache_entries")
    op.drop_table("cache_entries")


def downgrade() -> None:
    import sqlalchemy as sa

    op.create_table(
        "cache_entries",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("cache_type", sa.String(length=64), nullable=False),
        sa.Column("cache_key", sa.String(length=512), nullable=False),
        sa.Column("content_hash", sa.String(length=128), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=False),
        sa.Column("rule_pack_version", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("blob_pointer", sa.String(length=1024), nullable=True),
        sa.UniqueConstraint("cache_type", "cache_key", name="uq_cache_type_key"),
    )
    op.create_index("ix_cache_entries_last_used_at", "cache_entries", ["last_used_at"])

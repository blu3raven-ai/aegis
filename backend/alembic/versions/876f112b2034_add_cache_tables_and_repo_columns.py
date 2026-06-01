"""add cache tables and repo columns

Revision ID: 876f112b2034
Revises: 9de8c6a3b86f
Create Date: 2026-05-31 04:55:25.381555

Phase 0: cache schema for incremental scanning (Phase 2 fills it).
- cache_entries: generic per-tool cache (SBOMs, file-hash maps, etc.)
- verified_secrets: verified-secret cache by (detector_id, secret_hash)
- repos: new table with manifest_set_hash + last_scanned_sha for delta detection
Nothing reads from these yet; Phase 2 begins reading.

Note: the initial schema (9de8c6a3b86f) has no standalone repos table —
it uses source_connections + scan_checkpoints to track repo scope. This
migration introduces `repos` as the Phase 2 incremental-scan state store.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '876f112b2034'
down_revision: Union[str, Sequence[str], None] = '9de8c6a3b86f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cache_entries",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("cache_type", sa.String(64), nullable=False),
        sa.Column("cache_key", sa.String(512), nullable=False),
        sa.Column("content_hash", sa.String(128), nullable=False),
        sa.Column("tool_version", sa.String(64), nullable=False),
        sa.Column("rule_pack_version", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("blob_pointer", sa.String(1024), nullable=True),
        sa.UniqueConstraint("cache_type", "cache_key", name="uq_cache_type_key"),
    )
    op.create_index("ix_cache_entries_last_used_at", "cache_entries", ["last_used_at"])

    op.create_table(
        "verified_secrets",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("detector_id", sa.String(128), nullable=False),
        sa.Column("secret_hash", sa.String(128), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("ttl_until", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("detector_id", "secret_hash", name="uq_detector_secret"),
    )
    op.create_index("ix_verified_secrets_ttl", "verified_secrets", ["ttl_until"])

    # repos table did not exist in the initial schema; create it here as the
    # per-repo scan-state store for incremental scanning in Phase 2.
    op.create_table(
        "repos",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("org", sa.String(255), nullable=False),
        sa.Column("repo", sa.String(255), nullable=False),
        sa.Column("manifest_set_hash", sa.String(128), nullable=True),
        sa.Column("last_scanned_sha", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("org", "repo", name="uq_repos_org_repo"),
    )


def downgrade() -> None:
    op.drop_table("repos")
    op.drop_index("ix_verified_secrets_ttl", table_name="verified_secrets")
    op.drop_table("verified_secrets")
    op.drop_index("ix_cache_entries_last_used_at", table_name="cache_entries")
    op.drop_table("cache_entries")

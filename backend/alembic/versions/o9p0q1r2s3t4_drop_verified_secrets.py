"""drop verified_secrets table

Revision ID: o9p0q1r2s3t4
Revises: n8o9p0q1r2s3
Create Date: 2026-06-02

Removes the verified_secrets cache table. The backend no longer re-verifies
secrets after discovery — a secret committed to history is a leak regardless
of whether the credential still authenticates today, so the per-secret
re-verification cache served no purpose and has been deleted.
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'o9p0q1r2s3t4'
down_revision: Union[str, Sequence[str], None] = 'n8o9p0q1r2s3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_verified_secrets_ttl", table_name="verified_secrets")
    op.drop_table("verified_secrets")


def downgrade() -> None:
    import sqlalchemy as sa

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

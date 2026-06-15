"""add finding verification and llm config

Revision ID: 5dc205191450
Revises: 29e7adbf895b
Create Date: 2026-06-14 16:42:48.686950

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "5dc205191450"
down_revision = "29e7adbf895b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("verdict", sa.String(length=20), nullable=True))
    op.add_column("findings", sa.Column("evidence_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("findings", sa.Column("exploit_chain", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("verification_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_check_constraint(
        "ck_findings_verdict",
        "findings",
        "verdict IS NULL OR verdict IN ('confirmed','needs_verify','possible','ruled_out')",
    )
    op.create_index("ix_findings_verdict", "findings", ["verdict"])

    op.create_table(
        "llm_config",
        sa.Column("org_id", sa.String(length=255), primary_key=True),
        sa.Column("api_key_enc", sa.String(length=512), nullable=False),
        sa.Column("api_base_url", sa.String(length=512), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("scan_token_budget", sa.Integer(), nullable=False, server_default="100000"),
        sa.Column("daily_token_budget", sa.Integer(), nullable=False, server_default="1000000"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "llm_usage_daily",
        sa.Column("org_id", sa.String(length=255), primary_key=True),
        sa.Column("date", sa.Date(), primary_key=True),
        sa.Column("tokens_in", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("scans", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

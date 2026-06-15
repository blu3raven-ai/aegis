"""add audit_stream_config singleton table

Revision ID: u7v8w9x0y1z2
Revises: a36b76bd2ab5
Create Date: 2026-06-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "u7v8w9x0y1z2"
down_revision = "a36b76bd2ab5"


def upgrade() -> None:
    op.create_table(
        "audit_stream_config",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("endpoint_url", sa.Text(), nullable=True),
        sa.Column("auth_token_enc", sa.Text(), nullable=True),
        sa.Column("last_event_id", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("id = 1", name="ck_audit_stream_config_singleton"),
    )
    op.execute("INSERT INTO audit_stream_config (id) VALUES (1)")


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

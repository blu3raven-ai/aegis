"""add scim_config singleton table

Revision ID: t6u7v8w9x0y1
Revises: e7dfd6e839c9
Create Date: 2026-06-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t6u7v8w9x0y1"
down_revision = "e7dfd6e839c9"


def upgrade() -> None:
    op.create_table(
        "scim_config",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("token_hash", sa.String(length=128), nullable=True),
        sa.Column(
            "default_role_id",
            sa.String(length=255),
            sa.ForeignKey("roles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_scim_config_singleton"),
    )
    op.execute("INSERT INTO scim_config (id) VALUES (1)")


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

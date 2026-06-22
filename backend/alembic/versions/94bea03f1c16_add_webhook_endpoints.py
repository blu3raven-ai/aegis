"""add webhook_endpoints table

Revision ID: 94bea03f1c16
Revises: 3cb39a73c326
Create Date: 2026-06-16
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "94bea03f1c16"
down_revision = "3cb39a73c326"
branch_labels = None
depends_on = None


_PROVIDERS = ("github", "gitlab", "bitbucket", "azure_devops", "jenkins")


def upgrade() -> None:
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("org_id", sa.String(length=255), nullable=False, server_default="default"),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("secret_enc", sa.Text(), nullable=False),
        sa.Column("last4", sa.String(length=4), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "provider", name="uq_webhook_endpoints_org_provider"),
        sa.CheckConstraint(
            "provider IN ('" + "','".join(_PROVIDERS) + "')",
            name="ck_webhook_endpoints_provider",
        ),
    )
    op.create_index(
        "ix_webhook_endpoints_provider",
        "webhook_endpoints",
        ["provider"],
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""add sso_config singleton table and sso columns on users

Revision ID: s5t6u7v8w9x0
Revises: 708dfe4ac7fc
Create Date: 2026-06-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "s5t6u7v8w9x0"
down_revision = "708dfe4ac7fc"


def upgrade() -> None:
    op.create_table(
        "sso_config",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column(
            "default_role_id",
            sa.String(length=255),
            sa.ForeignKey("roles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("saml_metadata_url", sa.Text(), nullable=True),
        sa.Column("saml_metadata_xml", sa.Text(), nullable=True),
        sa.Column("saml_sp_private_key_enc", sa.Text(), nullable=True),
        sa.Column("saml_sp_certificate", sa.Text(), nullable=True),
        sa.Column("oidc_discovery_url", sa.Text(), nullable=True),
        sa.Column("oidc_client_id", sa.String(length=255), nullable=True),
        sa.Column("oidc_client_secret_enc", sa.Text(), nullable=True),
        sa.Column(
            "oidc_scopes",
            sa.String(length=255),
            nullable=False,
            server_default="openid email profile",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_sso_config_singleton"),
    )
    op.execute("INSERT INTO sso_config (id) VALUES (1)")

    op.add_column("users", sa.Column("sso_subject", sa.String(length=512), nullable=True))
    op.add_column("users", sa.Column("sso_protocol", sa.String(length=16), nullable=True))
    op.create_index(
        "uq_users_sso_subject",
        "users",
        ["sso_subject"],
        unique=True,
        postgresql_where=sa.text("sso_subject IS NOT NULL"),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

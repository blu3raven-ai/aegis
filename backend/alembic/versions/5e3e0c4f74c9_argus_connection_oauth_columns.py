"""argus connection oauth columns

Replaces the static ``token_enc`` on ``argus_connection`` with OAuth fields:
the durable refresh token (encrypted) plus the token endpoint and client id used
to mint short-lived access tokens at scan-dispatch time.

Revision ID: 5e3e0c4f74c9
Revises: 113539e19e11
Create Date: 2026-06-29

"""
import sqlalchemy as sa
from alembic import op

revision = "5e3e0c4f74c9"
down_revision = "113539e19e11"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add the OAuth columns. server_default="" only to satisfy NOT NULL on any
    # pre-existing row; the table is new and the defaults are dropped below so
    # the final schema matches the model (no server default).
    op.add_column(
        "argus_connection",
        sa.Column("token_endpoint", sa.String(length=512), nullable=False, server_default=""),
    )
    op.add_column(
        "argus_connection",
        sa.Column("client_id", sa.String(length=255), nullable=False, server_default=""),
    )
    op.add_column(
        "argus_connection",
        sa.Column("refresh_token_enc", sa.String(length=2048), nullable=False, server_default=""),
    )
    op.drop_column("argus_connection", "token_enc")
    op.alter_column("argus_connection", "token_endpoint", server_default=None)
    op.alter_column("argus_connection", "client_id", server_default=None)
    op.alter_column("argus_connection", "refresh_token_enc", server_default=None)


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

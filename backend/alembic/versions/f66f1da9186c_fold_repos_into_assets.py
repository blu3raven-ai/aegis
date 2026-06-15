"""fold repos scan-state columns into assets and drop repos table

Revision ID: f66f1da9186c
Revises: s5t6u7v8w9x0
Create Date: 2026-06-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f66f1da9186c"
down_revision = "s5t6u7v8w9x0"


def upgrade() -> None:
    op.add_column("assets", sa.Column("manifest_set_hash", sa.String(length=128), nullable=True))
    op.add_column("assets", sa.Column("last_scanned_sha", sa.String(length=64), nullable=True))
    op.add_column("assets", sa.Column("tier", sa.String(length=32), nullable=True))
    op.add_column(
        "assets",
        sa.Column(
            "archived",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "assets",
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("assets", sa.Column("image_registry", sa.String(length=255), nullable=True))

    op.execute(
        """
        UPDATE assets a
        SET manifest_set_hash = r.manifest_set_hash,
            last_scanned_sha  = r.last_scanned_sha,
            tier              = r.tier,
            archived          = r.archived,
            labels            = r.labels,
            image_registry    = r.image_registry
        FROM repos r
        WHERE r.asset_id = a.id
        """
    )

    op.drop_index("ix_repos_asset_id", table_name="repos")
    op.drop_table("repos")


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

"""migrate scan_checkpoints from (tool, org, repo) to (tool, asset_id)

Revision ID: af43d38e6bbe
Revises: 89a16b0078dc
Create Date: 2026-06-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "af43d38e6bbe"
down_revision = "89a16b0078dc"


def upgrade() -> None:
    # Add asset_id column (nullable for the backfill window).
    op.add_column(
        "scan_checkpoints",
        sa.Column("asset_id", sa.UUID(as_uuid=False), nullable=True),
    )

    # Backfill: match (org, repo) to assets by display_name. Display name is
    # set to "<org>/<repo>" everywhere we ingest source-connection repos, so
    # this join captures the entire universe of pre-migration rows.
    op.execute(
        """
        UPDATE scan_checkpoints sc
        SET asset_id = a.id
        FROM assets a
        WHERE a.type = 'repo'
          AND a.display_name = sc.org || '/' || sc.repo
        """
    )

    # Drop rows that didn't match an asset — they belong to repos no source
    # connection ever surfaced into the asset table. Keeping them would be
    # dead state pointing at nothing.
    op.execute("DELETE FROM scan_checkpoints WHERE asset_id IS NULL")

    # Lock down the new identity.
    op.alter_column("scan_checkpoints", "asset_id", nullable=False)
    op.create_foreign_key(
        "fk_scan_checkpoints_asset_id",
        "scan_checkpoints",
        "assets",
        ["asset_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # Swap primary key from (tool, org, repo) to (tool, asset_id).
    op.drop_constraint("scan_checkpoints_pkey", "scan_checkpoints", type_="primary")
    op.create_primary_key(
        "scan_checkpoints_pkey", "scan_checkpoints", ["tool", "asset_id"]
    )

    op.drop_column("scan_checkpoints", "org")
    op.drop_column("scan_checkpoints", "repo")


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

"""Add asset identity layer.

Creates assets and team_assets. Adds nullable asset_id to findings, repos,
scan_runs, sboms, finding_sla_status, rule_violations, direct_grants.
Legacy org/repo columns are kept until the final cleanup commit so the code
migration can land incrementally.

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-06-07
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "f5a6b7c8d9e0"
down_revision = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", UUID(as_uuid=False), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("source_ref", sa.String(255), nullable=True),
        sa.Column("external_ref", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(512), nullable=False),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("external_ref", name="uq_assets_external_ref"),
        sa.CheckConstraint("type IN ('repo','image')", name="ck_assets_type"),
        sa.CheckConstraint(
            "source IN ('source_connection','manual_upload','byo_import')",
            name="ck_assets_source",
        ),
    )
    op.create_index("ix_assets_source_ref", "assets", ["source_ref"])
    op.create_index("ix_assets_type", "assets", ["type"])

    op.create_table(
        "team_assets",
        sa.Column("team_id", sa.String(255),
                  sa.ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("asset_id", UUID(as_uuid=False),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("source", sa.String(50), nullable=False, server_default=sa.text("'manual'")),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_team_assets_asset_id", "team_assets", ["asset_id"])

    # Add nullable asset_id to existing tables. NOT NULL is enforced in Task 18
    # after code migration has populated the column.
    for tbl in ("findings", "repos", "scan_runs", "sboms",
                "finding_sla_status", "rule_violations", "direct_grants"):
        op.add_column(tbl,
            sa.Column("asset_id", UUID(as_uuid=False),
                      sa.ForeignKey("assets.id", ondelete="RESTRICT"),
                      nullable=True),
        )
        op.create_index(f"ix_{tbl}_asset_id", tbl, ["asset_id"])


def downgrade() -> None:
    for tbl in ("findings", "repos", "scan_runs", "sboms",
                "finding_sla_status", "rule_violations", "direct_grants"):
        op.drop_index(f"ix_{tbl}_asset_id", table_name=tbl)
        op.drop_column(tbl, "asset_id")
    op.drop_index("ix_team_assets_asset_id", table_name="team_assets")
    op.drop_table("team_assets")
    op.drop_index("ix_assets_type", table_name="assets")
    op.drop_index("ix_assets_source_ref", table_name="assets")
    op.drop_table("assets")

"""drop denormalized asset_id from finding_sla_status; finding_id already keys the row

Revision ID: d7ac13b64466
Revises: af43d38e6bbe
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op

revision = "d7ac13b64466"
down_revision = "af43d38e6bbe"


def upgrade() -> None:
    op.drop_index("ix_finding_sla_status_asset_id", table_name="finding_sla_status")
    op.drop_column("finding_sla_status", "asset_id")


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

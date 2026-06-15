"""drop denormalized tool/identity_key columns from finding_events

Both columns mirror Finding.tool / Finding.identity_key — values that are
immutable per finding (they're part of the uq_finding_tool_asset_key
constraint), so the snapshot adds no information not derivable via the
finding_id FK join. No reader queries FindingEvent.tool or
FindingEvent.identity_key directly; every consumer joins through
finding_id.

Revision ID: 593038952b6d
Revises: 713b432e0824
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op

revision = "593038952b6d"
down_revision = "713b432e0824"


def upgrade() -> None:
    op.drop_column("finding_events", "tool")
    op.drop_column("finding_events", "identity_key")


def downgrade() -> None:
    raise NotImplementedError("Forward-only schema; no downgrade.")

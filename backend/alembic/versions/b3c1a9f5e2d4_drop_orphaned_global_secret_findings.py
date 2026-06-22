"""drop orphaned instance-global secret findings (pre per-source scoping)

Secret findings used to be instance-global (asset_id IS NULL) and were never
surfaced through the asset-scoped findings list. Per-source scoping now attaches
each secret to its repo asset, so the old asset-less rows are dead data — drop
them; a re-scan recreates them attached to their repo assets.

Revision ID: b3c1a9f5e2d4
Revises: d4e2b8f16a37
Create Date: 2026-06-21
"""
from __future__ import annotations

from alembic import op

revision = "b3c1a9f5e2d4"
down_revision = "d4e2b8f16a37"


def upgrade() -> None:
    # finding_events FK is ON DELETE NO ACTION — remove children first.
    op.execute(
        "DELETE FROM finding_events WHERE finding_id IN "
        "(SELECT id FROM findings WHERE tool = 'secret_scanning' AND asset_id IS NULL)"
    )
    # finding_sla_status cascades with the finding delete.
    op.execute(
        "DELETE FROM findings WHERE tool = 'secret_scanning' AND asset_id IS NULL"
    )
    op.execute(
        "DELETE FROM decisions WHERE tool = 'secret_scanning' AND asset_id IS NULL"
    )
    op.execute(
        "DELETE FROM scan_checkpoints WHERE tool = 'secret_scanning' AND asset_id IS NULL"
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

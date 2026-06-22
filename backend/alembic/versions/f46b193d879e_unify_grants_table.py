"""unify grants table — replace team_assets + direct_grants

Collapses the two separate grant tables into a single `grants` table keyed on
(subject_type, subject_id, asset_id). Existing rows are migrated:
  - team_assets  → subject_type='team', subject_id=team_id
  - direct_grants → subject_type='user', subject_id=user_id

Forward-only per CLAUDE.md.

Revision ID: f46b193d879e
Revises: 846aeeca99a7
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID


revision: str = "f46b193d879e"
down_revision: Union[str, Sequence[str], None] = "846aeeca99a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "grants",
        sa.Column("subject_type", sa.String(10), nullable=False),
        sa.Column("subject_id", sa.String(255), nullable=False),
        sa.Column(
            "asset_id",
            UUID(as_uuid=False),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(50), nullable=False, server_default="manual"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("subject_type", "subject_id", "asset_id"),
        sa.CheckConstraint("subject_type IN ('user', 'team')", name="ck_grants_subject_type"),
    )
    op.create_index("ix_grants_asset_id", "grants", ["asset_id"])
    op.create_index("ix_grants_subject", "grants", ["subject_type", "subject_id"])

    # Backfill from team_assets
    op.execute(
        sa.text(
            """
            INSERT INTO grants (subject_type, subject_id, asset_id, source, created_at)
            SELECT 'team', team_id, asset_id, source, added_at
            FROM team_assets
            ON CONFLICT DO NOTHING
            """
        )
    )

    # Backfill from direct_grants
    op.execute(
        sa.text(
            """
            INSERT INTO grants (subject_type, subject_id, asset_id, source, created_at)
            SELECT 'user', user_id, asset_id, source, granted_at
            FROM direct_grants
            ON CONFLICT DO NOTHING
            """
        )
    )

    op.drop_table("team_assets")
    op.drop_table("direct_grants")


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

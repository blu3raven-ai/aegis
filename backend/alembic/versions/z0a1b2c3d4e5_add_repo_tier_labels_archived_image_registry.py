"""add tier, archived, labels, image_registry columns to repos

Revision ID: z0a1b2c3d4e5
Revises: y9z0a1b2c3d4
Create Date: 2026-06-05

Scanner-coverage rules predicate on repo tier, archival state, labels, and
container registry. This migration adds the four columns the rule evaluator
needs; existing rows default to archived=false and NULL for the rest.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "z0a1b2c3d4e5"
down_revision = "y9z0a1b2c3d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("repos", sa.Column("tier", sa.String(32), nullable=True))
    op.add_column(
        "repos",
        sa.Column(
            "archived",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column("repos", sa.Column("labels", postgresql.JSONB(), nullable=True))
    op.add_column("repos", sa.Column("image_registry", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("repos", "image_registry")
    op.drop_column("repos", "labels")
    op.drop_column("repos", "archived")
    op.drop_column("repos", "tier")

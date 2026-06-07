"""Add nullable assignee_user_id column to findings.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-06-06
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "e4f5a6b7c8d9"
down_revision = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("assignee_user_id", sa.String(255), nullable=True),
    )
    op.create_foreign_key(
        "fk_findings_assignee_user_id",
        "findings",
        "users",
        ["assignee_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_finding_org_assignee",
        "findings",
        ["org", "assignee_user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_finding_org_assignee", table_name="findings")
    op.drop_constraint("fk_findings_assignee_user_id", "findings", type_="foreignkey")
    op.drop_column("findings", "assignee_user_id")

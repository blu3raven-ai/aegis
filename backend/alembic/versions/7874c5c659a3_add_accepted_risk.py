"""add accepted_risk table

Revision ID: 7874c5c659a3
Revises: c4d9b2e7f1a8
Create Date: 2026-07-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = '7874c5c659a3'
down_revision: Union[str, Sequence[str], None] = 'c4d9b2e7f1a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "accepted_risk",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", UUID(as_uuid=False), nullable=True),
        sa.Column("source_connection_id", sa.String(length=255), nullable=True),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("path_glob", sa.String(length=512), nullable=True),
        sa.Column("rule_id", sa.String(length=256), nullable=True),
        sa.Column("scanner", sa.String(length=64), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_connection_id"], ["source_connections.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_accepted_risk_asset_id", "accepted_risk", ["asset_id"])
    op.create_index("ix_accepted_risk_source_connection_id", "accepted_risk", ["source_connection_id"])


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

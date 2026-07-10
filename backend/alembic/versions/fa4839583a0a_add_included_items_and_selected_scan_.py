"""add included_items and selected scan scope

Revision ID: fa4839583a0a
Revises: a1c3e8f2d94b
Create Date: 2026-07-10 15:13:02.348686

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'fa4839583a0a'
down_revision: Union[str, Sequence[str], None] = 'a1c3e8f2d94b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "source_connections",
        sa.Column("included_items", JSONB, nullable=False, server_default="[]"),
    )
    # Widen the scan_scope check to allow the new "selected" (cherry-pick) mode.
    op.drop_constraint("ck_source_connections_scan_scope", "source_connections", type_="check")
    op.create_check_constraint(
        "ck_source_connections_scan_scope",
        "source_connections",
        "scan_scope IN ('all', 'all-except-excluded', 'selected')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

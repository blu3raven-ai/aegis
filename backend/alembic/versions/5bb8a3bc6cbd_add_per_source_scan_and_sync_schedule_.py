"""add per-source scan and sync schedule fields

Revision ID: 5bb8a3bc6cbd
Revises: 352f65aa0d5b
Create Date: 2026-06-21 01:08:15.251102

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5bb8a3bc6cbd'
down_revision: Union[str, Sequence[str], None] = '352f65aa0d5b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "source_connections",
        sa.Column("sync_schedule_mode", sa.String(length=10), nullable=False, server_default="preset"),
    )
    op.add_column(
        "source_connections",
        sa.Column("sync_schedule_cron", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "source_connections",
        sa.Column("scan_auto_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "source_connections",
        sa.Column("scan_schedule_mode", sa.String(length=10), nullable=False, server_default="preset"),
    )
    op.add_column(
        "source_connections",
        sa.Column("scan_schedule_preset", sa.String(length=50), nullable=False, server_default="24h"),
    )
    op.add_column(
        "source_connections",
        sa.Column("scan_schedule_cron", sa.String(length=120), nullable=True),
    )
    op.create_check_constraint(
        "ck_source_connections_scan_schedule_preset",
        "source_connections",
        "scan_schedule_preset IN ('1h', '3h', '6h', '12h', '24h')",
    )
    op.create_check_constraint(
        "ck_source_connections_sync_schedule_mode",
        "source_connections",
        "sync_schedule_mode IN ('preset', 'cron')",
    )
    op.create_check_constraint(
        "ck_source_connections_scan_schedule_mode",
        "source_connections",
        "scan_schedule_mode IN ('preset', 'cron')",
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

"""add osv mirror tables

Revision ID: 352f65aa0d5b
Revises: f46b193d879e
Create Date: 2026-06-17 09:58:29.804635

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "352f65aa0d5b"
down_revision: Union[str, Sequence[str], None] = "f46b193d879e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "osv_advisories",
        sa.Column("advisory_id", sa.String(64), primary_key=True),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("blob_key", sa.String(256), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_osv_advisories_modified_at", "osv_advisories", ["modified_at"])
    op.create_index("ix_osv_advisories_ecosystem", "osv_advisories", ["ecosystem"])

    op.create_table(
        "osv_vulnerable_ranges",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("advisory_id", sa.String(64), nullable=False),
        sa.Column("package_name", sa.String(256), nullable=False),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("range_introduced", sa.String(128), nullable=True),
        sa.Column("range_fixed", sa.String(128), nullable=True),
        sa.Column("range_last_affected", sa.String(128), nullable=True),
        sa.ForeignKeyConstraint(
            ["advisory_id"],
            ["osv_advisories.advisory_id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_osv_ranges_pkg_eco", "osv_vulnerable_ranges", ["ecosystem", "package_name"])

    op.create_table(
        "osv_refresh_runs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("advisories_added", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("advisories_changed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("jobs_enqueued", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

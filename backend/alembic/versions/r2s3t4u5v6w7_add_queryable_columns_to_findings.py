"""add queryable columns to findings

Revision ID: r2s3t4u5v6w7
Revises: q1r2s3t4u5v6
Create Date: 2026-06-02

"""
from __future__ import annotations

from alembic import op


revision = "r2s3t4u5v6w7"
down_revision = "q1r2s3t4u5v6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    import sqlalchemy as sa

    op.add_column("findings", sa.Column("cve_id", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("file_path", sa.String(length=1024), nullable=True))
    op.add_column("findings", sa.Column("title", sa.String(length=512), nullable=True))
    op.add_column("findings", sa.Column("rule_name", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("package_name", sa.String(length=512), nullable=True))

    # Partial btree indexes — each column is sparse (many NULLs across the
    # findings table because most rows don't have every field). Partial
    # WHERE clauses keep the index small.
    op.create_index(
        "ix_findings_cve_id",
        "findings",
        ["cve_id"],
        postgresql_where=sa.text("cve_id IS NOT NULL"),
    )
    op.create_index(
        "ix_findings_file_path",
        "findings",
        ["file_path"],
        postgresql_where=sa.text("file_path IS NOT NULL"),
    )
    op.create_index(
        "ix_findings_rule_name",
        "findings",
        ["rule_name"],
        postgresql_where=sa.text("rule_name IS NOT NULL"),
    )
    op.create_index(
        "ix_findings_package_name",
        "findings",
        ["package_name"],
        postgresql_where=sa.text("package_name IS NOT NULL"),
    )
    # Composite for the KEV/EPSS join hot path.
    op.create_index(
        "ix_findings_org_cve_id",
        "findings",
        ["org", "cve_id"],
        postgresql_where=sa.text("cve_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_findings_org_cve_id", table_name="findings")
    op.drop_index("ix_findings_package_name", table_name="findings")
    op.drop_index("ix_findings_rule_name", table_name="findings")
    op.drop_index("ix_findings_file_path", table_name="findings")
    op.drop_index("ix_findings_cve_id", table_name="findings")
    op.drop_column("findings", "package_name")
    op.drop_column("findings", "rule_name")
    op.drop_column("findings", "title")
    op.drop_column("findings", "file_path")
    op.drop_column("findings", "cve_id")

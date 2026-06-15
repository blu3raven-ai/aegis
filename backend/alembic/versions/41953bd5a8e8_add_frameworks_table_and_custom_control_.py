"""add compliance framework tables

Revision ID: 41953bd5a8e8
Revises: b05903d2c795
Create Date: 2026-06-15 00:51:18.799408

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "41953bd5a8e8"
down_revision = "b05903d2c795"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "frameworks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "is_custom",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("created_by_user_id", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    frameworks_table = sa.table(
        "frameworks",
        sa.column("id", sa.String(64)),
        sa.column("label", sa.String(255)),
        sa.column("is_custom", sa.Boolean()),
    )
    op.bulk_insert(
        frameworks_table,
        [
            {"id": "soc2", "label": "SOC 2", "is_custom": False},
            {"id": "iso27001", "label": "ISO 27001", "is_custom": False},
            {"id": "pci-dss", "label": "PCI DSS", "is_custom": False},
        ],
    )

    op.create_table(
        "framework_controls",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("framework", sa.String(64), nullable=False),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(128), nullable=True),
        sa.Column(
            "is_custom",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("created_by_user_id", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["framework"], ["frameworks.id"],
            name="fk_framework_controls_framework",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("framework", "control_id", name="uq_framework_control"),
    )
    op.create_index(
        "ix_framework_controls_fw",
        "framework_controls",
        ["framework"],
    )

    op.create_table(
        "compliance_control_mappings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.BigInteger(), nullable=True),
        sa.Column("framework", sa.String(64), nullable=False),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_compliance_finding",
        "compliance_control_mappings",
        ["finding_id"],
    )
    op.create_index(
        "ix_compliance_framework_control",
        "compliance_control_mappings",
        ["framework", "control_id"],
    )


def downgrade() -> None:
    raise NotImplementedError("Forward-only; no downgrade.")

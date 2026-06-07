"""add rules and rule_violations tables for unified rules engine

Revision ID: x8y9z0a1b2c3
Revises: w7x8y9z0a1b2
Create Date: 2026-06-04
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "x8y9z0a1b2c3"
down_revision = "w7x8y9z0a1b2"


def upgrade() -> None:
    op.create_table(
        "rules",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("org_id", sa.String(255), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("conditions", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("action", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_rules_org_category", "rules", ["org_id", "category"])
    op.create_index("ix_rules_org_enabled", "rules", ["org_id", "enabled"])

    op.create_table(
        "rule_violations",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.String(64), sa.ForeignKey("rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("opened_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("context", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_rule_violations_rule_status", "rule_violations", ["rule_id", "status"])
    op.create_index("ix_rule_violations_subject", "rule_violations", ["subject_type", "subject_id"])
    op.create_index(
        "uq_rule_violations_open_per_subject",
        "rule_violations",
        ["rule_id", "subject_type", "subject_id"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )

    # Backfill SLA rules from existing sla_policies — one row per (org, severity).
    op.execute("""
        INSERT INTO rules (id, org_id, category, name, conditions, action, created_by, created_at, updated_at, enabled)
        SELECT
            'sla-' || severity || '-' || substring(encode(sha256(org_id::bytea), 'hex') for 16) AS id,
            org_id,
            'sla' AS category,
            INITCAP(severity) || ' findings · ' || deadline_days || '-day SLA' AS name,
            jsonb_build_object('field', 'severity', 'op', 'eq', 'value', severity) AS conditions,
            jsonb_build_object('deadline_days', deadline_days, 'escalations', '[]'::jsonb) AS action,
            'migration' AS created_by,
            created_at,
            updated_at,
            enabled
        FROM sla_policies;
    """)


def downgrade() -> None:
    op.drop_index("uq_rule_violations_open_per_subject", table_name="rule_violations")
    op.drop_index("ix_rule_violations_subject", table_name="rule_violations")
    op.drop_index("ix_rule_violations_rule_status", table_name="rule_violations")
    op.drop_table("rule_violations")
    op.drop_index("ix_rules_org_enabled", table_name="rules")
    op.drop_index("ix_rules_org_category", table_name="rules")
    op.drop_table("rules")

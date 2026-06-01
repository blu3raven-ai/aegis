"""add sla_policies and finding_sla_status tables for Phase 47

Revision ID: h2i3j4k5l6m7
Revises: g1h2i3j4k5l6
Create Date: 2026-05-31 00:00:00.000000

Phase 47: per-severity SLA policies for compliance-driven remediation tracking.
sla_policies stores configurable deadlines per org and severity; finding_sla_status
is a computed projection updated hourly so the dashboard can aggregate breach state
without scanning every finding row inline.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = 'h2i3j4k5l6m7'
down_revision: Union[str, Sequence[str], None] = 'g1h2i3j4k5l6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'sla_policies',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('org_id', sa.String(255), nullable=False),
        sa.Column('severity', sa.String(10), nullable=False),
        sa.Column('deadline_days', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('org_id', 'severity', name='uq_sla_policy_org_severity'),
    )
    op.create_index('ix_sla_policies_org_id', 'sla_policies', ['org_id'])

    op.create_table(
        'finding_sla_status',
        sa.Column('finding_id', sa.Integer(), sa.ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('deadline_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('breached', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('breach_age_days', sa.Integer(), nullable=True),
        sa.Column('computed_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_finding_sla_status_breached', 'finding_sla_status', ['breached'])


def downgrade() -> None:
    op.drop_index('ix_finding_sla_status_breached', table_name='finding_sla_status')
    op.drop_table('finding_sla_status')
    op.drop_index('ix_sla_policies_org_id', table_name='sla_policies')
    op.drop_table('sla_policies')

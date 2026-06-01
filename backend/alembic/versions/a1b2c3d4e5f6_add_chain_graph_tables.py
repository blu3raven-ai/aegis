"""add chain graph tables (chains + chain_edges)

Revision ID: a1b2c3d4e5f6
Revises: 876f112b2034
Create Date: 2026-05-31 00:00:00.000000

Phase 3a: chain graph store for the correlation engine.
- chains: one row per attack chain; links to findings via chain_edges
- chain_edges: directed edges connecting two findings within a chain,
  tagged with edge_type, confidence, and the rule that produced the edge

Neither table is read by any active path yet — the correlation engine ships
dormant and is wired in as a follow-up "flip the switch" step.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '876f112b2034'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "chains",
        sa.Column("id", sa.String(26), primary_key=True),  # ULID
        sa.Column("org_id", sa.String(255), nullable=False),
        sa.Column("chain_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("last_updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("ai_explanation_id", sa.String(255), nullable=True),
    )
    op.create_index("ix_chains_org_id", "chains", ["org_id"])
    op.create_index("ix_chains_org_severity", "chains", ["org_id", "severity"])
    op.create_index("ix_chains_org_type", "chains", ["org_id", "chain_type"])
    op.create_index("ix_chains_status", "chains", ["status"])

    op.create_table(
        "chain_edges",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("chain_id", sa.String(26),
                  sa.ForeignKey("chains.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_finding_id", sa.Integer, nullable=False),
        sa.Column("target_finding_id", sa.Integer, nullable=False),
        sa.Column("edge_type", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("provenance_rule", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        # Prevent duplicate edges for the same (chain, src, tgt, type)
        sa.UniqueConstraint(
            "chain_id", "source_finding_id", "target_finding_id", "edge_type",
            name="uq_chain_edge_dedup",
        ),
    )
    op.create_index("ix_chain_edges_chain_id", "chain_edges", ["chain_id"])
    op.create_index("ix_chain_edges_source", "chain_edges", ["source_finding_id"])
    op.create_index("ix_chain_edges_target", "chain_edges", ["target_finding_id"])


def downgrade() -> None:
    op.drop_index("ix_chain_edges_target", table_name="chain_edges")
    op.drop_index("ix_chain_edges_source", table_name="chain_edges")
    op.drop_index("ix_chain_edges_chain_id", table_name="chain_edges")
    op.drop_table("chain_edges")

    op.drop_index("ix_chains_status", table_name="chains")
    op.drop_index("ix_chains_org_type", table_name="chains")
    op.drop_index("ix_chains_org_severity", table_name="chains")
    op.drop_index("ix_chains_org_id", table_name="chains")
    op.drop_table("chains")

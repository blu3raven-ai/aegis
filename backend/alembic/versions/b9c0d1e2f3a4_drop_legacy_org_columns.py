"""Drop legacy org/repo columns and team_repositories/team_container_images.

Revision ID: b9c0d1e2f3a4
Revises: f5a6b7c8d9e0
Create Date: 2026-06-07
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "b9c0d1e2f3a4"
down_revision = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── drop legacy home-dashboard materialized views ─────────────────────────
    # These MVs are grouped by findings.org and block the column drop below.
    # PR #406 (Plan B) moved home-dashboard reads off them to query findings
    # directly, so they're dead. Drop with IF EXISTS in case a partial earlier
    # run already removed them.
    for view in (
        "mv_findings_summary",
        "mv_home_analytics_repo",
        "mv_home_analytics_age",
        "mv_home_remediation",
    ):
        op.execute(f"DROP MATERIALIZED VIEW IF EXISTS {view}")

    # ── decisions — add asset_id, backfill from findings, drop org ────────────
    op.add_column("decisions",
        sa.Column("asset_id", UUID(as_uuid=False),
                  sa.ForeignKey("assets.id", ondelete="RESTRICT"),
                  nullable=True))
    op.execute("""
        UPDATE decisions d SET asset_id = f.asset_id
        FROM findings f
        WHERE d.tool = f.tool
          AND d.org = f.org
          AND d.identity_key = f.identity_key
          AND f.asset_id IS NOT NULL
    """)
    op.create_index("ix_decisions_asset_identity", "decisions",
                    ["asset_id", "tool", "identity_key"])
    op.drop_index("ix_decision_tool_org", table_name="decisions")
    op.drop_constraint("uq_decision_tool_org_key", "decisions", type_="unique")
    op.drop_column("decisions", "org")
    op.create_unique_constraint("uq_decision_tool_asset_key", "decisions",
                                ["tool", "asset_id", "identity_key"])

    # ── findings — drop org/repo, replace constraints ─────────────────────────
    op.drop_constraint("uq_finding_tool_org_key", "findings", type_="unique")
    op.drop_index("ix_finding_tool_org_state", table_name="findings")
    op.drop_index("ix_finding_tool_org_severity", table_name="findings")
    op.drop_index("ix_finding_tool_org_repo", table_name="findings")
    op.drop_index("ix_finding_org_assignee", table_name="findings")
    op.drop_column("findings", "org")
    op.drop_column("findings", "repo")
    # Secrets findings keep asset_id=NULL; Postgres UNIQUE allows duplicate NULLs.
    op.create_unique_constraint("uq_finding_tool_asset_key", "findings",
                                ["tool", "asset_id", "identity_key"])
    op.create_index("ix_finding_asset_state", "findings", ["asset_id", "state"])
    op.create_index("ix_finding_asset_severity", "findings", ["asset_id", "severity"])
    op.create_index("ix_finding_asset_assignee", "findings",
                    ["asset_id", "assignee_user_id"])

    # ── scan_runs — drop org, NOT NULL asset_id ───────────────────────────────
    op.drop_index("ix_scanrun_tool_org_status", table_name="scan_runs")
    op.drop_column("scan_runs", "org")

    # ── sbom_components — add asset_id + sbom_id, BACKFILL BOTH from sboms ──
    # Must run before sboms.org/repo are dropped because the backfill joins on them.
    op.add_column("sbom_components",
        sa.Column("asset_id", UUID(as_uuid=False),
                  sa.ForeignKey("assets.id", ondelete="RESTRICT"),
                  nullable=True))
    op.add_column("sbom_components",
        sa.Column("sbom_id", sa.Integer,
                  sa.ForeignKey("sboms.id", ondelete="CASCADE"),
                  nullable=True))
    op.execute("""
        UPDATE sbom_components sc
        SET asset_id = s.asset_id, sbom_id = s.id
        FROM sboms s
        WHERE sc.org = s.org AND sc.repo = s.repo
    """)
    # Delete any rows whose parent sbom couldn't be located (orphans) so the
    # NOT NULL alter below doesn't fail.
    op.execute("DELETE FROM sbom_components WHERE asset_id IS NULL")

    # ── sboms — drop org/repo, NOT NULL asset_id, replace constraint ──────────
    op.drop_constraint("uq_sbom_org_repo", "sboms", type_="unique")
    op.drop_column("sboms", "org")
    op.drop_column("sboms", "repo")
    op.alter_column("sboms", "asset_id", nullable=False)
    op.create_unique_constraint("uq_sbom_asset", "sboms", ["asset_id"])

    # ── sbom_components — drop legacy indexes/columns, NOT NULL, new constraints ──
    op.drop_index("idx_sbom_components_name", table_name="sbom_components")
    op.drop_index("idx_sbom_components_purl", table_name="sbom_components")
    op.drop_constraint("uq_sbom_components_org_repo_purl", "sbom_components",
                       type_="unique")
    op.drop_column("sbom_components", "org")
    op.drop_column("sbom_components", "repo")
    op.alter_column("sbom_components", "asset_id", nullable=False)
    op.create_index("idx_sbom_components_asset_name", "sbom_components",
                    ["asset_id", "name", "ecosystem"])
    op.create_index("idx_sbom_components_asset_purl", "sbom_components",
                    ["asset_id", "purl"])
    op.create_unique_constraint("uq_sbom_components_asset_purl", "sbom_components",
                                ["asset_id", "purl"])

    # ── repos — drop org/repo, NOT NULL asset_id, replace constraint ──────────
    op.drop_constraint("uq_repos_org_repo", "repos", type_="unique")
    op.drop_column("repos", "org")
    op.drop_column("repos", "repo")
    op.alter_column("repos", "asset_id", nullable=False)
    op.create_unique_constraint("uq_repos_asset", "repos", ["asset_id"])

    # ── finding_sla_status — NOT NULL asset_id ────────────────────────────────
    op.alter_column("finding_sla_status", "asset_id", nullable=False)

    # ── rule_violations — NOT NULL asset_id ──────────────────────────────────
    op.alter_column("rule_violations", "asset_id", nullable=False)

    # ── direct_grants — drop legacy columns, NOT NULL asset_id ───────────────
    try:
        op.drop_column("direct_grants", "org")
    except Exception:
        pass
    try:
        op.drop_column("direct_grants", "resource_type")
    except Exception:
        pass
    try:
        op.drop_column("direct_grants", "resource_name")
    except Exception:
        pass
    op.alter_column("direct_grants", "asset_id", nullable=False)

    # ── drop legacy team grant tables ─────────────────────────────────────────
    op.drop_table("team_container_images")
    op.drop_table("team_repositories")


def downgrade() -> None:
    raise RuntimeError(
        "downgrade not supported: legacy org/repo data was dropped without preservation"
    )

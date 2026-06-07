"""add home dashboard materialised views

Revision ID: t4u5v6w7x8y9
Revises: s3t4u5v6w7x8
Create Date: 2026-06-03

"""
from __future__ import annotations

from alembic import op


revision = "t4u5v6w7x8y9"
down_revision = "s3t4u5v6w7x8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # mv_findings_summary — KPI counts grouped by (org, tool, state, severity)
    op.execute("""
        CREATE MATERIALIZED VIEW mv_findings_summary AS
        SELECT org, tool, state, severity, count(*) AS finding_count
        FROM findings
        GROUP BY org, tool, state, severity
    """)
    op.execute("CREATE UNIQUE INDEX ix_mv_findings_summary_pk ON mv_findings_summary(org, tool, state, severity)")

    # mv_home_analytics_repo — per-repo open/critical/high counts for Top Repositories
    op.execute("""
        CREATE MATERIALIZED VIEW mv_home_analytics_repo AS
        SELECT
            org,
            repo,
            count(*) FILTER (WHERE state = 'open') AS open_count,
            count(*) FILTER (WHERE state = 'open' AND lower(severity) = 'critical') AS critical_count,
            count(*) FILTER (WHERE state = 'open' AND lower(severity) = 'high') AS high_count
        FROM findings
        GROUP BY org, repo
    """)
    op.execute("CREATE UNIQUE INDEX ix_mv_home_analytics_repo_pk ON mv_home_analytics_repo(org, repo)")

    # mv_home_analytics_age — counts by age bucket. Note: now() captured at refresh time.
    op.execute("""
        CREATE MATERIALIZED VIEW mv_home_analytics_age AS
        SELECT
            org,
            CASE
                WHEN (now() - first_seen_at) < interval '7 days' THEN '< 7 days'
                WHEN (now() - first_seen_at) < interval '30 days' THEN '7-30 days'
                WHEN (now() - first_seen_at) < interval '90 days' THEN '30-90 days'
                ELSE '> 90 days'
            END AS age_bucket,
            count(*) AS finding_count
        FROM findings
        WHERE state = 'open' AND first_seen_at IS NOT NULL
        GROUP BY org, age_bucket
    """)
    op.execute("CREATE UNIQUE INDEX ix_mv_home_analytics_age_pk ON mv_home_analytics_age(org, age_bucket)")

    # mv_home_remediation — fix-duration stats per org
    op.execute("""
        CREATE MATERIALIZED VIEW mv_home_remediation AS
        SELECT
            org,
            count(*) AS total_fixed,
            avg(extract(epoch from (fixed_at - first_seen_at)) / 86400) AS avg_days,
            percentile_cont(0.5) WITHIN GROUP (
                ORDER BY extract(epoch from (fixed_at - first_seen_at)) / 86400
            ) AS median_days,
            count(*) FILTER (WHERE fixed_at >= now() - interval '30 days') AS fixed_last_30d
        FROM findings
        WHERE state = 'fixed'
          AND fixed_at IS NOT NULL
          AND first_seen_at IS NOT NULL
          AND fixed_at >= now() - interval '365 days'
        GROUP BY org
    """)
    op.execute("CREATE UNIQUE INDEX ix_mv_home_remediation_pk ON mv_home_remediation(org)")


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS mv_home_remediation")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS mv_home_analytics_age")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS mv_home_analytics_repo")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS mv_findings_summary")

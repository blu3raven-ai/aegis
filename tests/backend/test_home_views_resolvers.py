"""Integration tests for the MV-backed GraphQL resolver rewrites.

Each test seeds real Finding rows, refreshes the materialised views,
then calls the resolver directly and asserts on the result shape.

The MVs are created once per module (same DDL as migration t4u5v6w7x8y9)
and the testcontainers Postgres is started by conftest.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy import delete as sa_delete

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.home_views import REFRESH_VIEWS


# ---------------------------------------------------------------------------
# Module-scoped fixture: create the 4 materialised views once
# ---------------------------------------------------------------------------

_MV_DDL = [
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS mv_findings_summary AS
    SELECT org, tool, state, severity, count(*) AS finding_count
    FROM findings
    GROUP BY org, tool, state, severity
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_mv_findings_summary_pk ON mv_findings_summary(org, tool, state, severity)",

    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS mv_home_analytics_repo AS
    SELECT
        org,
        repo,
        count(*) FILTER (WHERE state = 'open') AS open_count,
        count(*) FILTER (WHERE state = 'open' AND lower(severity) = 'critical') AS critical_count,
        count(*) FILTER (WHERE state = 'open' AND lower(severity) = 'high') AS high_count
    FROM findings
    GROUP BY org, repo
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_mv_home_analytics_repo_pk ON mv_home_analytics_repo(org, repo)",

    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS mv_home_analytics_age AS
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
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_mv_home_analytics_age_pk ON mv_home_analytics_age(org, age_bucket)",

    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS mv_home_remediation AS
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
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_mv_home_remediation_pk ON mv_home_remediation(org)",
]


@pytest.fixture(scope="module", autouse=True)
def _create_views():
    """Create all 4 MVs once for this test module."""
    async def _q(session):
        for ddl in _MV_DDL:
            await session.execute(sa.text(ddl))

    run_db(_q)
    yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_and_refresh(rows: list[dict]) -> None:
    async def _q(session):
        session.add_all([Finding(**row) for row in rows])
        await session.flush()
        for view in REFRESH_VIEWS:
            await session.execute(sa.text(f"REFRESH MATERIALIZED VIEW {view}"))

    run_db(_q)


def _clean(org: str) -> None:
    async def _q(session):
        await session.execute(sa_delete(Finding).where(Finding.org == org))
        for view in REFRESH_VIEWS:
            await session.execute(sa.text(f"REFRESH MATERIALIZED VIEW {view}"))

    run_db(_q)


def _utc(**kwargs) -> datetime:
    return datetime.now(timezone.utc) - timedelta(**kwargs)


def _make_ctx(org: str) -> dict:
    return {"user_id": "test-user", "role": "admin", "orgs": [org], "tier": "pro", "request": None, "_cache": {}}


# ---------------------------------------------------------------------------
# test_dependencies_counts_with_mv
# ---------------------------------------------------------------------------

def test_dependencies_counts_with_mv():
    from src.graphql.dependencies_resolvers import dependencies_counts

    org = "rv-dep-counts"
    _clean(org)
    _seed_and_refresh([
        {"tool": "dependencies", "org": org, "repo": f"{org}/r", "identity_key": "d1",
         "state": "open", "severity": "critical"},
        {"tool": "dependencies", "org": org, "repo": f"{org}/r", "identity_key": "d2",
         "state": "open", "severity": "high"},
        {"tool": "dependencies", "org": org, "repo": f"{org}/r", "identity_key": "d3",
         "state": "open", "severity": "medium"},
        {"tool": "dependencies", "org": org, "repo": f"{org}/r", "identity_key": "d4",
         "state": "fixed", "severity": "critical"},
    ])

    result = dependencies_counts(org=org, info_context=_make_ctx(org))

    assert result.critical == 1
    assert result.high == 1
    assert result.medium == 1
    assert result.low == 0
    assert result.total == 3  # only open


# ---------------------------------------------------------------------------
# test_code_scanning_counts_with_mv
# ---------------------------------------------------------------------------

def test_code_scanning_counts_with_mv():
    from src.graphql.code_scanning_resolvers import code_scanning_counts

    org = "rv-cs-counts"
    _clean(org)
    _seed_and_refresh([
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "cs1",
         "state": "open", "severity": "high"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "cs2",
         "state": "open", "severity": "high"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "cs3",
         "state": "open", "severity": "critical"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "cs4",
         "state": "fixed", "severity": "high"},
    ])

    result = code_scanning_counts(org=org, info_context=_make_ctx(org))

    assert result.critical == 1
    assert result.high == 2
    assert result.medium == 0
    assert result.low == 0
    assert result.total == 3


# ---------------------------------------------------------------------------
# test_container_counts_with_mv
# ---------------------------------------------------------------------------

def test_container_counts_with_mv():
    from src.graphql.containers_resolvers import container_counts

    org = "rv-ct-counts"
    _clean(org)
    _seed_and_refresh([
        {"tool": "container_scanning", "org": org, "repo": f"{org}/img", "identity_key": "ct1",
         "state": "open", "severity": "medium"},
        {"tool": "container_scanning", "org": org, "repo": f"{org}/img", "identity_key": "ct2",
         "state": "open", "severity": "low"},
        {"tool": "container_scanning", "org": org, "repo": f"{org}/img", "identity_key": "ct3",
         "state": "dismissed", "severity": "high"},
    ])

    result = container_counts(org=org, info_context=_make_ctx(org))

    assert result.critical == 0
    assert result.high == 0
    assert result.medium == 1
    assert result.low == 1
    assert result.total == 2


# ---------------------------------------------------------------------------
# test_secret_counts_with_mv
# ---------------------------------------------------------------------------

def test_secret_counts_with_mv():
    from src.graphql.secrets_resolvers import secret_counts

    org = "rv-sec-counts"
    _clean(org)
    _seed_and_refresh([
        {"tool": "secrets", "org": org, "repo": f"{org}/r", "identity_key": "s1",
         "state": "open", "severity": "high"},
        {"tool": "secrets", "org": org, "repo": f"{org}/r", "identity_key": "s2",
         "state": "open", "severity": "high"},
        {"tool": "secrets", "org": org, "repo": f"{org}/r", "identity_key": "s3",
         "state": "open", "severity": "critical"},
    ])

    result = secret_counts(org=org, info_context=_make_ctx(org))

    assert result.high == 2
    assert result.critical == 1
    assert result.total == 3


# ---------------------------------------------------------------------------
# test_home_analytics_returns_top_repos_age_buckets_remediation
# ---------------------------------------------------------------------------

def test_home_analytics_returns_top_repos_age_buckets_remediation():
    from src.graphql.posture_resolvers import home_analytics

    org = "rv-home-analytics"
    _clean(org)
    now = datetime.now(timezone.utc)
    _seed_and_refresh([
        # Open finding in repo-a (critical), recent
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-a",
         "identity_key": "ha1", "state": "open", "severity": "critical",
         "first_seen_at": _utc(days=3)},
        # Open finding in repo-b (high), older
        {"tool": "dependencies", "org": org, "repo": f"{org}/repo-b",
         "identity_key": "ha2", "state": "open", "severity": "high",
         "first_seen_at": _utc(days=50)},
        # Fixed finding (within last 30d)
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-a",
         "identity_key": "ha3", "state": "fixed", "severity": "high",
         "first_seen_at": now - timedelta(days=20),
         "fixed_at": now - timedelta(days=10)},
    ])

    ctx = {"user_id": "test", "role": "admin", "orgs": [org]}
    result = home_analytics(info_context=ctx)

    # top_repositories: should include repo-a (1 critical)
    repo_names = [r.name for r in result.top_repositories]
    assert len(repo_names) >= 1
    assert f"{org}/repo-a" in repo_names

    # age_buckets: 4 buckets returned
    assert len(result.age_buckets) == 4
    bucket_labels = {b.label for b in result.age_buckets}
    assert bucket_labels == {"< 7 days", "7-30 days", "30-90 days", "> 90 days"}

    # remediation
    assert result.remediation.total_fixed == 1
    assert result.remediation.fixed_last_30d == 1


# ---------------------------------------------------------------------------
# test_home_analytics_empty_orgs_returns_zeros
# ---------------------------------------------------------------------------

def test_home_analytics_empty_orgs_returns_zeros():
    from src.graphql.posture_resolvers import home_analytics

    ctx = {"user_id": "test", "role": "admin", "orgs": []}
    result = home_analytics(info_context=ctx)

    assert result.top_repositories == []
    assert result.age_buckets == []
    assert result.remediation.total_fixed == 0
    assert result.remediation.avg_days is None
    assert result.remediation.median_days is None
    assert result.remediation.fixed_last_30d == 0

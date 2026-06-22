"""Integration tests for home_views read helpers.

Requires testcontainers Postgres (started by conftest.py).

The conftest creates ORM-defined tables via Base.metadata.create_all.
Materialised views are not ORM models, so we create them here in a
module-scoped fixture using the same DDL as migration t4u5v6w7x8y9.

Each test uses an isolated org name to avoid cross-test interference.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy import delete as sa_delete

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.home_views import (
    REFRESH_VIEWS,
    get_age_buckets,
    get_remediation_stats,
    get_severity_counts,
    get_top_repositories,
    refresh_all_home_views,
)


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
# Seed + refresh helper
# ---------------------------------------------------------------------------

def _seed_and_refresh(rows: list[dict]) -> None:
    """Insert findings and refresh all 4 MVs.

    :param rows: dicts of Finding constructor kwargs
    """
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


# ---------------------------------------------------------------------------
# get_severity_counts
# ---------------------------------------------------------------------------

def test_get_severity_counts_returns_zeros_for_empty_orgs():
    result = get_severity_counts([], tool="code_scanning")
    assert result == {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


def test_get_severity_counts_with_data():
    org = "hv-sev-counts"
    _clean(org)
    _seed_and_refresh([
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo", "identity_key": "k1",
         "state": "open", "severity": "critical"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo", "identity_key": "k2",
         "state": "open", "severity": "high"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo", "identity_key": "k3",
         "state": "open", "severity": "high"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo", "identity_key": "k4",
         "state": "open", "severity": "medium"},
    ])

    result = get_severity_counts([org], tool="code_scanning", state="open")
    assert result["critical"] == 1
    assert result["high"] == 2
    assert result["medium"] == 1
    assert result["low"] == 0
    assert result["total"] == 4


def test_get_severity_counts_filters_by_tool():
    org = "hv-sev-tool"
    _clean(org)
    _seed_and_refresh([
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo", "identity_key": "cs1",
         "state": "open", "severity": "critical"},
        {"tool": "dependencies", "org": org, "repo": f"{org}/repo", "identity_key": "dep1",
         "state": "open", "severity": "high"},
    ])

    cs = get_severity_counts([org], tool="code_scanning")
    assert cs["critical"] == 1
    assert cs["high"] == 0
    assert cs["total"] == 1

    dep = get_severity_counts([org], tool="dependencies_scanning")
    assert dep["high"] == 1
    assert dep["critical"] == 0
    assert dep["total"] == 1


def test_get_severity_counts_filters_by_state():
    org = "hv-sev-state"
    _clean(org)
    _seed_and_refresh([
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo", "identity_key": "open1",
         "state": "open", "severity": "high"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo", "identity_key": "fixed1",
         "state": "fixed", "severity": "critical",
         "fixed_at": _utc(days=1), "first_seen_at": _utc(days=10)},
    ])

    open_counts = get_severity_counts([org], tool="code_scanning", state="open")
    assert open_counts["high"] == 1
    assert open_counts["critical"] == 0

    fixed_counts = get_severity_counts([org], tool="code_scanning", state="fixed")
    assert fixed_counts["critical"] == 1
    assert fixed_counts["high"] == 0


# ---------------------------------------------------------------------------
# get_top_repositories
# ---------------------------------------------------------------------------

def test_get_top_repositories_ordering():
    org = "hv-top-repo-order"
    _clean(org)
    _seed_and_refresh([
        # repo-a: 1 critical, 0 high
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-a", "identity_key": "a1",
         "state": "open", "severity": "critical"},
        # repo-b: 0 critical, 3 high
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-b", "identity_key": "b1",
         "state": "open", "severity": "high"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-b", "identity_key": "b2",
         "state": "open", "severity": "high"},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-b", "identity_key": "b3",
         "state": "open", "severity": "high"},
        # repo-c: 0 critical, 1 high
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-c", "identity_key": "c1",
         "state": "open", "severity": "high"},
    ])

    result = get_top_repositories([org], limit=5)
    names = [r["name"] for r in result]

    # repo-a (1 critical) must come before repo-b (0 critical)
    assert names.index(f"{org}/repo-a") < names.index(f"{org}/repo-b")
    # repo-b (3 high) must come before repo-c (1 high)
    assert names.index(f"{org}/repo-b") < names.index(f"{org}/repo-c")


def test_get_top_repositories_limit():
    org = "hv-top-repo-limit"
    _clean(org)
    _seed_and_refresh([
        {"tool": "code_scanning", "org": org, "repo": f"{org}/repo-{i}",
         "identity_key": f"lim{i}", "state": "open", "severity": "high"}
        for i in range(10)
    ])

    result = get_top_repositories([org], limit=3)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# get_age_buckets
# ---------------------------------------------------------------------------

def test_get_age_buckets_returns_default_for_empty_orgs():
    result = get_age_buckets([])
    assert result == {"< 7 days": 0, "7-30 days": 0, "30-90 days": 0, "> 90 days": 0}


def test_get_age_buckets_with_data():
    org = "hv-age-buckets"
    _clean(org)
    _seed_and_refresh([
        # < 7 days
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "age1",
         "state": "open", "severity": "high", "first_seen_at": _utc(days=2)},
        # 7-30 days
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "age2",
         "state": "open", "severity": "high", "first_seen_at": _utc(days=15)},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "age3",
         "state": "open", "severity": "high", "first_seen_at": _utc(days=20)},
        # 30-90 days
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "age4",
         "state": "open", "severity": "high", "first_seen_at": _utc(days=45)},
        # > 90 days
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "age5",
         "state": "open", "severity": "high", "first_seen_at": _utc(days=120)},
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "age6",
         "state": "open", "severity": "high", "first_seen_at": _utc(days=200)},
    ])

    result = get_age_buckets([org])
    assert result["< 7 days"] == 1
    assert result["7-30 days"] == 2
    assert result["30-90 days"] == 1
    assert result["> 90 days"] == 2


# ---------------------------------------------------------------------------
# get_remediation_stats
# ---------------------------------------------------------------------------

def test_get_remediation_stats_returns_default_for_empty_orgs():
    result = get_remediation_stats([])
    assert result == {"total_fixed": 0, "avg_days": None, "median_days": None, "fixed_last_30d": 0}


def test_get_remediation_stats_with_data():
    org = "hv-remediation"
    _clean(org)
    now = datetime.now(timezone.utc)
    _seed_and_refresh([
        # Fixed 10 days ago, took 5 days to fix
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "rem1",
         "state": "fixed", "severity": "high",
         "first_seen_at": now - timedelta(days=15),
         "fixed_at": now - timedelta(days=10)},
        # Fixed 5 days ago, took 10 days to fix
        {"tool": "code_scanning", "org": org, "repo": f"{org}/r", "identity_key": "rem2",
         "state": "fixed", "severity": "critical",
         "first_seen_at": now - timedelta(days=15),
         "fixed_at": now - timedelta(days=5)},
    ])

    result = get_remediation_stats([org])
    assert result["total_fixed"] == 2
    # avg of 5 and 10 = 7.5
    assert result["avg_days"] == pytest.approx(7.5, abs=0.2)
    # median of [5, 10] = 7.5
    assert result["median_days"] == pytest.approx(7.5, abs=0.2)
    # both fixed within last 30 days
    assert result["fixed_last_30d"] == 2


# ---------------------------------------------------------------------------
# refresh_all_home_views smoke test
# ---------------------------------------------------------------------------

def test_refresh_all_home_views_smoke():
    """refresh_all_home_views must complete without raising and MVs must be queryable."""
    # Should not raise even when called multiple times.
    refresh_all_home_views()
    refresh_all_home_views()

    # All 4 views must be queryable after refresh.
    def _check(session):
        pass  # placeholder; real check below

    async def _query(session):
        for view in REFRESH_VIEWS:
            await session.execute(sa.text(f"SELECT 1 FROM {view} LIMIT 1"))

    run_db(_query)

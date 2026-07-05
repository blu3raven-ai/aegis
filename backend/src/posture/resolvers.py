"""Posture resolvers — snapshot, by-team, daily trend, and home analytics.

The trend resolver reads the pre-aggregated ``posture_snapshots`` table
(written nightly by ``compute_and_store_daily_snapshots``) so the chart
includes a daily ``risk_score`` value. Empty scope is fail-closed.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Optional

import strawberry

from src.graphql.resolver_utils import raise_bad_input
from src.graphql.types import (
    EpssTopFinding, HomeAgeBucket, HomeAnalytics, HomeRemediationStats,
    HomeRepoSummary, PostureTrendPoint,
)
from src.posture.service import (
    RISK_DIMENSIONS,
    get_exploitability_summary,
    get_posture_by_team,
    get_posture_snapshot,
    get_posture_trend,
    get_risk_contributions,
    get_scanner_breakdown,
    get_sla_posture,
)
from src.shared.home_views import (
    get_age_buckets_by_asset_ids,
    get_remediation_stats_by_asset_ids,
    get_top_repositories_by_asset_ids,
)


# ── Snapshot types ─────────────────────────────────────────────────────────

@strawberry.type
class PostureCounts:
    total: int
    critical: int
    high: int
    medium: int
    low: int
    unknown: int = 0


@strawberry.type
class SeverityDistributionItem:
    severity: str
    count: int
    percentage: int


@strawberry.type
class PostureAgeBucket:
    label: str
    count: int


@strawberry.type
class PostureTopRepository:
    name: str
    open: int
    critical: int
    high: int


@strawberry.type
class PostureRemediation:
    total_fixed: int
    avg_days: Optional[float]
    median_days: Optional[float]
    fixed_last_30d: int


@strawberry.type
class PostureRepositoryCoverage:
    total: int
    affected: int
    unaffected: int
    percentage: int


@strawberry.type
class PostureRiskScore:
    score: int
    rating: str
    summary: str


@strawberry.type
class PostureSnapshot:
    counts: PostureCounts
    severity_distribution: list[SeverityDistributionItem]
    age_buckets: list[PostureAgeBucket]
    top_repositories: list[PostureTopRepository]
    remediation: PostureRemediation
    repository_coverage: PostureRepositoryCoverage
    risk_score: PostureRiskScore


@strawberry.type
class TeamPosture:
    team_id: str
    team_name: str
    repo_count: int
    counts: PostureCounts
    risk_score: PostureRiskScore


# ── Resolvers ──────────────────────────────────────────────────────────────

def posture_snapshot(*, info_context: dict) -> PostureSnapshot:
    asset_ids = info_context.get("asset_ids") or []
    payload = get_posture_snapshot(asset_ids=asset_ids)
    d = asdict(payload)
    return PostureSnapshot(
        counts=PostureCounts(**d["counts"]),
        severity_distribution=[SeverityDistributionItem(**s) for s in d["severityDistribution"]],
        age_buckets=[PostureAgeBucket(**b) for b in d["ageBuckets"]],
        top_repositories=[PostureTopRepository(**r) for r in d["topRepositories"]],
        remediation=PostureRemediation(
            total_fixed=d["remediation"]["totalFixed"],
            avg_days=d["remediation"]["avgDays"],
            median_days=d["remediation"]["medianDays"],
            fixed_last_30d=d["remediation"]["fixedLast30d"],
        ),
        repository_coverage=PostureRepositoryCoverage(**d["repositoryCoverage"]),
        risk_score=PostureRiskScore(**d["riskScore"]),
    )


def posture_by_team(*, info_context: dict) -> list[TeamPosture]:
    asset_ids = info_context.get("asset_ids") or []
    rows = get_posture_by_team(asset_ids=asset_ids)
    return [
        TeamPosture(
            team_id=r["team_id"],
            team_name=r["team_name"],
            repo_count=r["repo_count"],
            counts=PostureCounts(**r["counts"]),
            risk_score=PostureRiskScore(**r["risk_score"]),
        )
        for r in rows
    ]


def posture_trend(*, days: int = 30, info_context: dict) -> list[PostureTrendPoint]:
    asset_ids = info_context.get("asset_ids") or []
    # Bound the window so abusive values can't reach the SQL layer.
    clamped = max(7, min(int(days), 365))
    rows = get_posture_trend(asset_ids=asset_ids, days=clamped)
    return [
        PostureTrendPoint(
            date=r["date"],
            total=r["total"],
            critical=r["critical"],
            high=r["high"],
            medium=r["medium"],
            low=r["low"],
            risk_score=r["risk_score"],
            new_findings=r.get("new_findings", 0),
        )
        for r in rows
    ]


def home_analytics(*, info_context: dict) -> HomeAnalytics:
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return HomeAnalytics(
            top_repositories=[],
            age_buckets=[],
            remediation=HomeRemediationStats(
                total_fixed=0, avg_days=None, median_days=None, fixed_last_30d=0,
            ),
        )

    top_repos = get_top_repositories_by_asset_ids(asset_ids, limit=5)
    age_buckets = get_age_buckets_by_asset_ids(asset_ids)
    rem = get_remediation_stats_by_asset_ids(asset_ids)

    return HomeAnalytics(
        top_repositories=[HomeRepoSummary(**r) for r in top_repos],
        age_buckets=[HomeAgeBucket(label=k, count=v) for k, v in age_buckets.items()],
        remediation=HomeRemediationStats(
            total_fixed=rem["total_fixed"],
            avg_days=rem["avg_days"],
            median_days=rem["median_days"],
            fixed_last_30d=rem["fixed_last_30d"],
        ),
    )



# ── Triage surface types ───────────────────────────────────────────────────

@strawberry.type
class ScannerBreakdownItem:
    scanner: str
    critical: int
    high: int
    medium: int
    low: int
    total: int
    risk_score: int
    sla_breached: int


@strawberry.type
class RiskContributionItem:
    dimension: str
    label: str
    risk_score: int
    count: int
    percentage: int


@strawberry.type
class ExploitabilitySummary:
    kev_count: int
    high_epss_count: int
    epss_top: list[EpssTopFinding]


@strawberry.type
class SlaBreachByScanner:
    scanner: str
    breached: int


@strawberry.type
class SlaPostureSummary:
    total_breached: int
    critical_breached: int
    high_breached: int
    medium_breached: int
    low_breached: int
    max_breach_age_days: int
    by_scanner: list[SlaBreachByScanner]


# ── Triage resolvers ───────────────────────────────────────────────────────

def scanner_breakdown(*, info_context: dict) -> list[ScannerBreakdownItem]:
    asset_ids = info_context.get("asset_ids") or []
    rows = get_scanner_breakdown(asset_ids=asset_ids)
    return [ScannerBreakdownItem(**r) for r in rows]


def risk_contributions(*, dimension: str, info_context: dict) -> list[RiskContributionItem]:
    if dimension not in RISK_DIMENSIONS:
        raise_bad_input(
            f"Invalid dimension '{dimension}'. Must be one of: {', '.join(RISK_DIMENSIONS)}."
        )
    asset_ids = info_context.get("asset_ids") or []
    rows = get_risk_contributions(asset_ids=asset_ids, dimension=dimension)
    return [RiskContributionItem(**r) for r in rows]


def exploitability_summary(*, info_context: dict) -> ExploitabilitySummary:
    asset_ids = info_context.get("asset_ids") or []
    data = get_exploitability_summary(asset_ids=asset_ids)
    return ExploitabilitySummary(
        kev_count=data["kev_count"],
        high_epss_count=data["high_epss_count"],
        epss_top=[
            EpssTopFinding(
                finding_id=int(f["finding_id"]),
                tool=str(f.get("tool", "")),
                repo=str(f.get("repo", "")),
                severity=str(f.get("severity", "")),
                identity_key=str(f.get("identity_key", "")),
                cve=str(f.get("cve", "")),
                epss_score=float(f.get("epss_score") or 0),
                epss_percentile=float(f.get("epss_percentile") or 0),
                scored_date=f.get("scored_date"),
            )
            for f in data["epss_top"]
        ],
    )


def sla_posture(*, info_context: dict) -> SlaPostureSummary:
    asset_ids = info_context.get("asset_ids") or []
    data = get_sla_posture(asset_ids=asset_ids)
    return SlaPostureSummary(
        total_breached=data["total_breached"],
        critical_breached=data["critical_breached"],
        high_breached=data["high_breached"],
        medium_breached=data["medium_breached"],
        low_breached=data["low_breached"],
        max_breach_age_days=data["max_breach_age_days"],
        by_scanner=[
            SlaBreachByScanner(scanner=r["scanner"], breached=r["breached"])
            for r in data["by_scanner"]
        ],
    )

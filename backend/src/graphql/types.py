"""Shared GraphQL types used across all tool resolvers."""
from __future__ import annotations

import strawberry
from typing import Optional


@strawberry.type
class PostureTrendPoint:
    date: str
    total: int
    critical: int
    high: int
    medium: int
    low: int


@strawberry.type
class HomeRepoSummary:
    name: str
    open: int
    critical: int
    high: int


@strawberry.type
class HomeAgeBucket:
    label: str
    count: int


@strawberry.type
class HomeRemediationStats:
    total_fixed: int
    avg_days: Optional[float]
    median_days: Optional[float]
    fixed_last_30d: int


@strawberry.type
class HomeAnalytics:
    top_repositories: list[HomeRepoSummary]
    age_buckets: list[HomeAgeBucket]
    remediation: HomeRemediationStats


@strawberry.type
class SeverityCounts:
    total: int
    critical: int
    high: int
    medium: int
    low: int


@strawberry.type
class PageInfo:
    has_next_page: bool
    has_previous_page: bool
    total_pages: int


@strawberry.type
class SeverityBucket:
    severity: str
    count: int
    percentage: int


@strawberry.type
class AgeBucket:
    label: str
    count: int


@strawberry.type
class RepoSummary:
    name: str
    open: int
    critical: int
    high: int


@strawberry.type
class RemediationStats:
    total_fixed: int
    avg_days: Optional[float]
    median_days: Optional[float]
    fixed_last_30d: int


@strawberry.type
class CoverageStats:
    total: int
    affected: int
    unaffected: int
    percentage: int


@strawberry.type
class RiskScore:
    score: int
    rating: str
    summary: str


@strawberry.type
class FilterOptions:
    ecosystems: list[str]
    repositories: list[str]
    organizations: list[str]


@strawberry.type
class CodeScanningRuleCount:
    rule_id: str
    rule_name: str
    count: int


@strawberry.type
class StateBreakdown:
    open: int
    dismissed: int
    fixed: int
    awaiting_fix: int


@strawberry.type
class CategoryCount:
    category: str
    count: int


@strawberry.type
class CodeScanningFilterOptions:
    repositories: list[str]
    languages: list[str]
    rule_ids: list[str]


@strawberry.type
class MonthlyTrendItem:
    month: str
    introduced: int
    resolved: int
    open_at_end: int


@strawberry.type
class EcosystemBreakdownItem:
    ecosystem: str
    critical: int
    high: int
    medium: int
    low: int
    total: int


@strawberry.type
class VulnerablePackage:
    name: str
    ecosystem: str
    repo_count: int
    critical: int
    high: int
    medium: int
    low: int


@strawberry.type
class MTTRBySeverity:
    critical: Optional[float]
    high: Optional[float]
    medium: Optional[float]
    low: Optional[float]


@strawberry.type
class RemediationPriorityRow:
    rank: int
    package_name: str
    ecosystem: str
    ghsa_id: str
    cve_id: Optional[str]
    severity: str
    repos_affected: int
    patch_version: Optional[str]
    advisory_url: str


@strawberry.type
class ClassificationEntry:
    value: str
    source: str
    scan_depth: Optional[str]
    confidence: Optional[float]
    run_id: Optional[str]
    scanned_at: Optional[str]


@strawberry.type
class ReviewFunnel:
    new_count: int
    confirmed_count: int
    false_positive_count: int
    action_taken_count: int


@strawberry.type
class SourceCount:
    source: str
    count: int


@strawberry.type
class SecretsRepoPriority:
    organization: str
    repository: str
    unreviewed_count: int
    confirmed_count: int


@strawberry.type
class SecretsOverview:
    unique_key_count: int
    total_findings_count: int
    review_funnel: ReviewFunnel
    source_breakdown: list[SourceCount]
    remediation: RemediationStats
    repository_coverage: CoverageStats
    stale_findings_count: int
    resolved_recently_count: int
    unresolved_count: int
    age_buckets: list[AgeBucket]
    triage_priority: list[SecretsRepoPriority]


@strawberry.type
class SecretsFilterOptions:
    organizations: list[str]
    repositories: list[str]
    detectors: list[str]
    sources: list[str]


# ── SLA breach summary types ──────────────────────────────────────────────────

@strawberry.type
class SeverityBreachStat:
    open: int
    breached: int
    breached_pct: float


@strawberry.type
class BreachSummary:
    critical: SeverityBreachStat
    high: SeverityBreachStat
    medium: SeverityBreachStat
    low: SeverityBreachStat


# ── EPSS top findings types ───────────────────────────────────────────────────

@strawberry.type
class EpssTopFinding:
    finding_id: int
    tool: str
    repo: str
    severity: str
    identity_key: str
    cve: str
    epss_score: float
    epss_percentile: float
    scored_date: Optional[str] = None


@strawberry.type
class EpssTopResponse:
    findings: list[EpssTopFinding]
    count: int


# ── Source connections types ──────────────────────────────────────────────────

@strawberry.type
class SourceAuth:
    org_or_owner: str


@strawberry.type
class SourceConnectionGQL:
    id: str
    source_type: str
    category: str
    name: str
    status: str
    auth: SourceAuth
    last_synced_at: Optional[str] = None
    next_sync_at: Optional[str] = None
    sync_schedule: Optional[str] = None


@strawberry.type
class SourceConnectionsResponse:
    connections: list[SourceConnectionGQL]

"""Shared GraphQL types used across all tool resolvers."""
from __future__ import annotations

import strawberry
from typing import Annotated, Optional, Union


@strawberry.type
class PostureTrendPoint:
    date: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    risk_score: int


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
class RiskScore:
    score: int
    rating: str
    summary: str


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



# ── Sources read surface (mirror of /api/v1/sources REST shapes) ────────────


@strawberry.type
class SourceFindingCounts:
    critical: int
    high: int
    medium: int
    low: int


@strawberry.type
class SourceRepoExtras:
    last_scanned_sha: Optional[str] = None
    manifest_set_hash: Optional[str] = None
    scanners_with_coverage: list[str] = strawberry.field(default_factory=list)
    coverage_status: str = "never"
    source_url: Optional[str] = None


@strawberry.type
class SourceImageExtras:
    image_digest: Optional[str] = None
    image_name: Optional[str] = None
    image_tag: Optional[str] = None
    layer_count: Optional[int] = None
    size_bytes: Optional[int] = None
    base_os: Optional[str] = None
    repos: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class SourceScanRunRow:
    scan_id: str
    scanner_type: str
    status: str
    started_at: str
    duration_ms: Optional[int] = None
    findings_count: int = 0


@strawberry.type
class SourceFindingRow:
    id: int
    tool: str
    severity: Optional[str]
    state: str
    identity_key: str
    asset_id: Optional[str]
    first_seen_at: str
    last_seen_at: str


@strawberry.type
class SourceRepoSummary:
    type: str
    asset_id: str
    display_name: Optional[str]
    last_scanned_at: Optional[str]
    finding_counts: SourceFindingCounts
    repo: SourceRepoExtras


@strawberry.type
class SourceImageSummary:
    type: str
    asset_id: str
    display_name: Optional[str]
    last_scanned_at: Optional[str]
    finding_counts: SourceFindingCounts
    image: SourceImageExtras


@strawberry.type
class SourceRepoDetail:
    type: str
    asset_id: str
    display_name: Optional[str]
    last_scanned_at: Optional[str]
    finding_counts: SourceFindingCounts
    repo: SourceRepoExtras
    scan_history: list[SourceScanRunRow]
    active_findings: list[SourceFindingRow]
    default_branch: Optional[str] = None


@strawberry.type
class SourceImageDetail:
    type: str
    asset_id: str
    display_name: Optional[str]
    last_scanned_at: Optional[str]
    finding_counts: SourceFindingCounts
    image: SourceImageExtras
    scan_history: list[SourceScanRunRow]
    active_findings: list[SourceFindingRow]


# Polymorphic detail — repo or image. Cloud has no detail loader in the
# service layer (and the REST endpoint never returned cloud), so it is not
# part of the union.
SourceDetail = Annotated[
    Union[SourceRepoDetail, SourceImageDetail],
    strawberry.union("SourceDetail"),
]


@strawberry.type
class RepoSourcesResponse:
    sources: list[SourceRepoSummary]
    next_cursor: Optional[str] = None
    total_count: Optional[int] = None


@strawberry.type
class ImageSourcesResponse:
    sources: list[SourceImageSummary]
    next_cursor: Optional[str] = None
    total_count: Optional[int] = None



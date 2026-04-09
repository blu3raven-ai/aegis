"""Vulnerability analytics builder.

Computes severity counts, age buckets, top repositories, remediation metrics,
repository coverage, and risk scores from finding dicts. Shared by SCA and
Container scanning.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.shared.paths import parse_iso_utc as _parse_dt


def _as_record(value: Any) -> dict[str, Any]:
    """Convert value to a dict if possible."""
    return value if isinstance(value, dict) else {}


@dataclass
class Counts:
    """Severity counts for alerts."""

    total: int
    critical: int
    high: int
    medium: int
    low: int


@dataclass
class SeverityDistributionItem:
    """Severity distribution with percentage."""

    severity: str
    count: int
    percentage: int


@dataclass
class AgeBucket:
    """Age bucket for alert age distribution."""

    label: str
    count: int


@dataclass
class TopRepository:
    """Repository with alert counts."""

    name: str
    open: int
    critical: int
    high: int


@dataclass
class RemediationMetrics:
    """Metrics for fixed alerts."""

    totalFixed: int
    avgDays: float | None
    medianDays: float | None
    fixedLast30d: int


@dataclass
class RepositoryCoverage:
    """Coverage metrics for repositories."""

    total: int
    affected: int
    unaffected: int
    percentage: int


@dataclass
class RiskScore:
    """Risk score with rating."""

    score: int
    rating: str
    summary: str


@dataclass
class AnalyticsPayload:
    """Complete analytics payload for dashboard."""

    counts: Counts
    severityDistribution: list[SeverityDistributionItem]
    ageBuckets: list[AgeBucket]
    topRepositories: list[TopRepository]
    remediation: RemediationMetrics
    repositoryCoverage: RepositoryCoverage
    riskScore: RiskScore


def get_counts(alerts: list[dict[str, Any]]) -> Counts:
    """Count alerts by severity."""
    critical = 0
    high = 0
    medium = 0
    low = 0

    for alert in alerts:
        advisory = _as_record(alert.get("security_advisory"))
        severity = advisory.get("severity", "")
        if severity == "critical":
            critical += 1
        elif severity == "high":
            high += 1
        elif severity == "medium":
            medium += 1
        elif severity == "low":
            low += 1

    return Counts(
        total=len(alerts),
        critical=critical,
        high=high,
        medium=medium,
        low=low,
    )


def get_severity_distribution(alerts: list[dict[str, Any]]) -> list[SeverityDistributionItem]:
    """Get severity distribution with percentages."""
    counts = get_counts(alerts)
    total = max(counts.total, 1)

    return [
        SeverityDistributionItem(
            severity="critical",
            count=counts.critical,
            percentage=round((counts.critical / total) * 100),
        ),
        SeverityDistributionItem(
            severity="high",
            count=counts.high,
            percentage=round((counts.high / total) * 100),
        ),
        SeverityDistributionItem(
            severity="medium",
            count=counts.medium,
            percentage=round((counts.medium / total) * 100),
        ),
        SeverityDistributionItem(
            severity="low",
            count=counts.low,
            percentage=round((counts.low / total) * 100),
        ),
    ]


def get_age_buckets(alerts: list[dict[str, Any]]) -> list[AgeBucket]:
    """Group alerts by age buckets."""
    buckets = [
        AgeBucket(label="0-7d", count=0),
        AgeBucket(label="8-30d", count=0),
        AgeBucket(label="31-90d", count=0),
        AgeBucket(label="90d+", count=0),
    ]

    now = datetime.now(timezone.utc).timestamp() * 1000

    for alert in alerts:
        created_at = alert.get("created_at", "")
        try:
            created_ms = _parse_dt(created_at).timestamp() * 1000
            age_days = (now - created_ms) / 86_400_000

            if age_days <= 7:
                buckets[0].count += 1
            elif age_days <= 30:
                buckets[1].count += 1
            elif age_days <= 90:
                buckets[2].count += 1
            else:
                buckets[3].count += 1
        except (ValueError, OSError):
            continue

    return buckets


def get_top_repositories(alerts: list[dict[str, Any]], limit: int = 5) -> list[TopRepository]:
    """Get top repositories by open alert count."""
    repo_map: dict[str, TopRepository] = {}

    for alert in alerts:
        repo = _as_record(alert.get("repository"))
        full_name = repo.get("full_name", "")
        if not full_name:
            continue

        existing = repo_map.get(full_name)
        if existing is None:
            existing = TopRepository(name=full_name, open=0, critical=0, high=0)
            repo_map[full_name] = existing

        # Update counts
        advisory = _as_record(alert.get("security_advisory"))
        severity = advisory.get("severity", "")

        existing.open += 1
        if severity == "critical":
            existing.critical += 1
        if severity == "high":
            existing.high += 1

    # Sort by critical, then high, then total open
    sorted_repos = sorted(
        repo_map.values(),
        key=lambda r: (-r.critical, -r.high, -r.open),
    )

    return sorted_repos[:limit]


def _get_median(values: list[float]) -> float | None:
    """Calculate median of a list of numbers."""
    if not values:
        return None
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    mid = n // 2
    if n % 2 == 0:
        return round((sorted_vals[mid - 1] + sorted_vals[mid]) * 10) / 10
    return round(sorted_vals[mid] * 10) / 10


def get_remediation_metrics(fixed_findings: list[dict[str, Any]]) -> RemediationMetrics:
    """Calculate remediation metrics from fixed findings."""
    durations: list[float] = []

    for alert in fixed_findings:
        fixed_at = alert.get("fixed_at")
        created_at = alert.get("created_at")
        if not fixed_at or not created_at:
            continue

        try:
            fixed_ms = _parse_dt(fixed_at).timestamp() * 1000
            created_ms = _parse_dt(created_at).timestamp() * 1000
            duration_days = max(0, (fixed_ms - created_ms) / 86_400_000)
            durations.append(duration_days)
        except (ValueError, OSError):
            continue

    total_fixed = len(durations)
    avg_days = round(sum(durations) / total_fixed * 10) / 10 if durations else None
    median_days = _get_median(durations)

    # Fixed in last 30 days
    now = datetime.now(timezone.utc).timestamp() * 1000
    fixed_last_30d = 0
    for alert in fixed_findings:
        fixed_at = alert.get("fixed_at")
        if not fixed_at:
            continue
        try:
            fixed_ms = _parse_dt(fixed_at).timestamp() * 1000
            if (now - fixed_ms) <= 30 * 86_400_000:
                fixed_last_30d += 1
        except (ValueError, OSError):
            continue

    return RemediationMetrics(
        totalFixed=total_fixed,
        avgDays=avg_days,
        medianDays=median_days,
        fixedLast30d=fixed_last_30d,
    )


def get_repository_coverage(
    open_findings: list[dict[str, Any]],
    repos: list[dict[str, Any]],
) -> RepositoryCoverage:
    """Calculate repository coverage metrics."""
    # Active repos (not archived or disabled)
    active_repos = [r for r in repos if not r.get("archived") and not r.get("disabled")]

    # Repos with open findings — match by id or full_name (case-insensitive)
    affected_keys: set[str] = set()
    for a in open_findings:
        repo = _as_record(a.get("repository"))
        repo_id = repo.get("id")
        full_name = repo.get("full_name", "")
        if repo_id:
            affected_keys.add(str(repo_id))
        if full_name:
            affected_keys.add(full_name.lower())

    total = len(active_repos)
    affected = sum(1 for r in active_repos if str(r.get("id", "")) in affected_keys or r.get("full_name", "").lower() in affected_keys)
    unaffected = max(total - affected, 0)
    percentage = round((affected / total) * 100) if total > 0 else 0

    return RepositoryCoverage(
        total=total,
        affected=affected,
        unaffected=unaffected,
        percentage=percentage,
    )


def get_risk_score(open_findings: list[dict[str, Any]]) -> RiskScore:
    """Calculate risk score based on severity mix.

    Risk score is the percentage of open findings that are critical or high severity.
    """
    counts = get_counts(open_findings)
    total = max(counts.total, 1)

    # Urgent share = critical + high as percentage of total
    urgent_share = (counts.critical + counts.high) / total
    score = max(0, min(100, round(urgent_share * 100)))

    # Determine rating
    if score >= 75:
        rating = "Severe"
        summary = "A large share of open issues are critical or high severity."
    elif score >= 55:
        rating = "High"
        summary = "High-severity work is a significant part of the open backlog."
    elif score >= 35:
        rating = "Moderate"
        summary = "Critical/high issues are present but not dominating the backlog."
    else:
        rating = "Low"
        summary = "Overall exposure is relatively contained right now."

    return RiskScore(score=score, rating=rating, summary=summary)


def build_analytics(
    open_findings: list[dict[str, Any]],
    fixed_findings: list[dict[str, Any]],
    repos: list[dict[str, Any]],
) -> AnalyticsPayload:
    """Build complete analytics payload from findings and repositories.

    Args:
        open_findings: List of open vulnerability findings
        fixed_findings: List of fixed vulnerability findings
        repos: List of repositories in the organization

    Returns:
        Complete analytics payload for dashboard
    """
    return AnalyticsPayload(
        counts=get_counts(open_findings),
        severityDistribution=get_severity_distribution(open_findings),
        ageBuckets=get_age_buckets(open_findings),
        topRepositories=get_top_repositories(open_findings),
        remediation=get_remediation_metrics(fixed_findings),
        repositoryCoverage=get_repository_coverage(open_findings, repos),
        riskScore=get_risk_score(open_findings),
    )

"""Vulnerability analytics builder.

Computes severity counts, age buckets, top repositories, remediation metrics,
repository coverage, and risk scores from finding dicts. Shared by SCA and
Container scanning.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.findings.action_band import action_band

from src.shared.paths import parse_iso_utc as _parse_dt


def _as_record(value: Any) -> dict[str, Any]:
    """Convert value to a dict if possible."""
    return value if isinstance(value, dict) else {}


@dataclass
class Counts:
    """Severity counts for alerts.

    ``unknown`` holds findings whose severity didn't resolve to one of the four
    named tiers (e.g. OSV matches with no severity). They still count toward
    ``total`` (they're real open findings) but carry no severity weight, so the
    severity distribution can show an explicit "unrated" slice and the risk
    score isn't deflated by findings it can't categorize.
    """

    total: int
    critical: int
    high: int
    medium: int
    low: int
    unknown: int = 0


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
    unknown = 0

    for alert in alerts:
        advisory = _as_record(alert.get("security_advisory"))
        severity = (advisory.get("severity") or "").lower()
        if severity == "critical":
            critical += 1
        elif severity == "high":
            high += 1
        elif severity == "medium":
            medium += 1
        elif severity == "low":
            low += 1
        else:
            unknown += 1

    return Counts(
        total=len(alerts),
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        unknown=unknown,
    )


def get_severity_distribution(alerts: list[dict[str, Any]]) -> list[SeverityDistributionItem]:
    """Get severity distribution with percentages.

    Includes an explicit ``unrated`` slice so the wedges sum to 100% of open
    findings rather than silently omitting unknown-severity ones.
    """
    counts = get_counts(alerts)
    total = max(counts.total, 1)

    items = [
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
    if counts.unknown:
        items.append(
            SeverityDistributionItem(
                severity="unrated",
                count=counts.unknown,
                percentage=round((counts.unknown / total) * 100),
            )
        )
    return items


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


# Severity weights for the aggregate posture risk score. Volume-weighted so a
# larger backlog of severe findings scores higher than a small one — a lone
# critical shouldn't read "Severe" any more than 50 criticals among 500 lows
# reads "Low" (the old proportion-only score did both). Same formula is used
# live (analytics) and in the nightly snapshot (posture.service) so the hero
# number and its trend line are on one scale. Unknown-severity findings carry
# no weight: they're real exposure but their severity is unresolvable, so they
# neither inflate nor deflate the score.
SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}


def posture_weighted_volume(*, critical: int, high: int, medium: int, low: int) -> int:
    """Raw additive weighted volume ``c*10 + h*5 + m*2 + l*1``.

    Additive and unbounded, so it's the right basis for *relative* comparison —
    per-scanner / per-repo risk contribution and "share of total risk" — where
    a concave gauge curve would distort each group's true proportion.
    """
    return (
        critical * SEVERITY_WEIGHTS["critical"] + high * SEVERITY_WEIGHTS["high"]
        + medium * SEVERITY_WEIGHTS["medium"] + low * SEVERITY_WEIGHTS["low"]
    )


# Curve constant for the headline gauge. A plain ``min(100, raw)`` pinned the
# score at 100 for any non-trivial backlog (10 criticals already maxed it), so
# the hero number and its trend flat-lined and couldn't show whether things
# were improving. The weighted volume is mapped through ``100 * (1 - e^(-raw/K))``
# instead: strictly increasing, so more findings always move the number, but
# approaching 100 asymptotically so the scale keeps discriminating across the
# whole realistic range. K sets where the rating bands land — with K=200,
# raw≈90 → Moderate(35), ≈160 → High(55), ≈277 → Severe(75); e.g. 9 crit +
# 34 high + 26 med + 8 low (raw 320) → 80.
RISK_GAUGE_K = 200


def posture_risk_gauge_from_raw(raw: float) -> int:
    """Map an (exploitability-)weighted raw volume onto the 0-100 gauge curve.

    ``100 * (1 - e^(-raw/K))`` (see ``RISK_GAUGE_K``): strictly increasing but
    asymptotic to 100, so the scale keeps discriminating without pinning. This
    is the single place the curve lives — hero, trend, and nightly snapshot all
    feed their summed raw through it so they stay on one scale.
    """
    if raw <= 0:
        return 0
    return min(100, max(0, round(100.0 * (1.0 - math.exp(-raw / RISK_GAUGE_K)))))


def posture_risk_gauge(*, critical: int, high: int, medium: int, low: int) -> int:
    """Severity-only convenience over the gauge (no exploitability weighting).

    Kept for callers that only have severity counts; the exploitability-aware
    path sums ``finding_exposure_weight`` per finding and calls
    ``posture_risk_gauge_from_raw`` directly.
    """
    return posture_risk_gauge_from_raw(
        posture_weighted_volume(critical=critical, high=high, medium=medium, low=low)
    )


# Exploitability multipliers layered on top of severity weight, keyed by the
# finding's SSVC action band. KEV-listed (actively exploited) and reachable
# high-severity findings weigh more; everything else is neutral (×1.0). The
# score is therefore *absence-neutral*: with no KEV/reachability signal every
# finding is Track (×1.0) and the sum reduces to the plain weighted volume, so
# the number is unchanged until enrichment data lands. EPSS is deliberately NOT
# an input — see findings/action_band.py.
BAND_MULTIPLIER = {"act": 2.5, "attend": 1.6, "track": 1.0}


def finding_exposure_weight(
    severity: str | None, *, kev_listed: bool = False, reachability: str | None = None,
) -> float:
    """One finding's contribution to the risk raw: ``severity_weight × band_mult``.

    Reuses ``action_band`` (Act/Attend/Track) as the single exploitability model
    so the posture score and the findings surface never diverge.
    """
    weight = SEVERITY_WEIGHTS.get((severity or "").lower(), 0)
    if weight == 0:
        return 0.0
    band = action_band(severity, kev_listed=kev_listed, reachability=reachability)
    return weight * BAND_MULTIPLIER.get(band, 1.0)


def get_risk_score(open_findings: list[dict[str, Any]]) -> RiskScore:
    """Aggregate posture risk score from the open findings.

    Each finding is weighted by severity AND exploitability (its action band —
    KEV-listed / reachable-high count more; see ``finding_exposure_weight``),
    then the summed raw is mapped onto the non-saturating gauge. Absence-neutral:
    with no KEV/reachability signal it reduces to pure severity volume. Matches
    the nightly snapshot's per-asset raw so the live number and its trend line
    stay on one scale.
    """
    raw = sum(
        finding_exposure_weight(
            (f.get("security_advisory") or {}).get("severity"),
            kev_listed=bool(f.get("kev_listed")),
            reachability=f.get("reachability"),
        )
        for f in open_findings
    )
    score = posture_risk_gauge_from_raw(raw)

    # Determine rating
    if score >= 75:
        rating = "Severe"
        summary = "A large volume of critical and high-severity findings is open."
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

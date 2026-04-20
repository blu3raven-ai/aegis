"""GraphQL resolvers for Secrets scanning."""
from __future__ import annotations

import math
from typing import Any, Optional

import strawberry

from src.graphql.auth import validate_org_access, GraphQLAuthError
from src.graphql.limits import clamp_per_page
from src.graphql.types import (
    SeverityCounts, PageInfo, ClassificationEntry, AgeBucket,
    ReviewFunnel, SourceCount, SecretsOverview, SecretsFilterOptions,
    RemediationStats, CoverageStats, SecretsRepoPriority,
)
from src.storage import read_latest_findings
from src.shared.paths import parse_iso_utc as _parse_dt


@strawberry.type
class SecretFinding:
    id: str
    state: str
    review_status: str
    detector: str
    file_path: str
    line: Optional[int]
    repository: str
    organization: str
    commit: Optional[str]
    secret_snippet: Optional[str]
    first_seen_at: Optional[str]
    dismissed_at: Optional[str]
    dismissed_by: Optional[str]
    dismissed_reason: Optional[str]
    secret_identity: Optional[str]
    fingerprint: Optional[str]
    source: str
    classification_history: list[ClassificationEntry]
    risk_score: Optional[float]
    occurrence_count: Optional[int]
    confirmed_at: Optional[str]
    resolved_at: Optional[str]
    detected_at: Optional[str]


@strawberry.type
class SecretFindingsConnection:
    items: list[SecretFinding]
    total_count: int
    page_info: PageInfo


def _load_scoped_findings(org: str, ctx: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Load secret findings with per-request caching and repo-level scope filtering."""
    if not ctx:
        raise GraphQLAuthError("Unauthorized")
    validate_org_access(ctx, org)
    cache_key = f"_secret_findings:{org}"
    request_cache = ctx.get("_cache")
    if request_cache is not None and cache_key in request_cache:
        return request_cache[cache_key]
    findings = read_latest_findings(org) or []
    request = ctx.get("request")
    if request:
        from src.shared.router_helpers import filter_by_user_scope
        findings = filter_by_user_scope(request, findings)
    if request_cache is not None:
        request_cache[cache_key] = findings
    return findings


def secret_counts(org: str, info_context: dict[str, Any]) -> SeverityCounts:
    """Count secrets by reviewStatus instead of severity.

    Maps:
      new           -> total (open)
      confirmed     -> high
      false_positive -> (excluded from total)
      action_taken  -> (excluded from total, same as fixed)
    """
    findings = _load_scoped_findings(org, info_context)
    # Count only findings that are not resolved
    active_statuses = {"new", "confirmed"}
    active = [f for f in findings if f.get("reviewStatus") in active_statuses]

    new_count = sum(1 for f in active if f.get("reviewStatus") == "new")
    confirmed_count = sum(1 for f in active if f.get("reviewStatus") == "confirmed")

    return SeverityCounts(
        total=len(active),
        # Map review statuses to severity buckets semantically:
        # critical = confirmed (needs immediate action)
        # high = new (unreviewed, potentially critical)
        # medium = 0 (secrets don't have medium granularity)
        # low = 0
        critical=confirmed_count,
        high=new_count,
        medium=0,
        low=0,
    )


def secret_findings(
    org: str,
    page: int = 1,
    per_page: int = 25,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    review_status: Optional[str] = None,
    detector: Optional[str] = None,
    repository: Optional[str] = None,
    organization: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    classification: Optional[str] = None,
    age_bucket: Optional[str] = None,
    new_since_last_scan: Optional[bool] = None,
    last_scan_date: Optional[str] = None,
    info_context: dict[str, Any] | None = None,
) -> SecretFindingsConnection:
    per_page = clamp_per_page(per_page)
    search = (search or "")[:200]
    findings = _load_scoped_findings(org, info_context)

    # For secrets: filter by state maps to reviewStatus
    if state:
        if state == "open":
            findings = [f for f in findings if f.get("reviewStatus") in ("new", "confirmed")]
        elif state == "fixed":
            findings = [f for f in findings if f.get("reviewStatus") == "action_taken"]
        elif state == "dismissed":
            findings = [f for f in findings if f.get("reviewStatus") == "false_positive"]
        else:
            findings = [f for f in findings if f.get("state") == state]

    # severity filter maps to reviewStatus for secrets
    if severity:
        if severity == "critical":
            findings = [f for f in findings if f.get("reviewStatus") == "confirmed"]
        elif severity == "high":
            findings = [f for f in findings if f.get("reviewStatus") == "new"]
        else:
            findings = []

    # New filters
    if review_status:
        findings = [f for f in findings if f.get("reviewStatus") == review_status]
    if detector:
        findings = [f for f in findings if f.get("detector") == detector]
    if repository:
        findings = [f for f in findings if f.get("repository") == repository]
    if organization:
        findings = [f for f in findings if f.get("organization") == organization]
    if source:
        findings = [f for f in findings if f.get("source") == source]
    if classification:
        def _has_classification(f: dict[str, Any]) -> bool:
            for entry in (f.get("classificationHistory") or []):
                if isinstance(entry, dict) and entry.get("value") == classification:
                    return True
            return False
        findings = [f for f in findings if _has_classification(f)]
    if age_bucket:
        import time
        from datetime import datetime
        normalized = age_bucket.replace("\u2013", "-")
        AGE_RANGES = {"< 7d": (0, 7), "7-30d": (7, 30), "1-3mo": (30, 90), "3-6mo": (90, 180), "6mo+": (180, 999999)}
        bounds = AGE_RANGES.get(normalized)
        if bounds:
            lo, hi = bounds
            now_s = time.time()
            def _age_days(f: dict[str, Any]) -> float:
                ca = f.get("detectedAt") or f.get("first_seen_at")
                if not ca:
                    return 0
                try:
                    return (now_s - _parse_dt(ca).timestamp()) / 86400
                except (ValueError, OSError):
                    return 0
            findings = [f for f in findings if lo <= _age_days(f) < hi]
    if new_since_last_scan and last_scan_date:
        findings = [f for f in findings if (f.get("detectedAt") or f.get("first_seen_at") or "") >= last_scan_date]
    if search:
        q = search.lower()
        def _matches(f: dict[str, Any]) -> bool:
            det = (f.get("detector") or "").lower()
            repo = (f.get("repository") or "").lower()
            fp = (f.get("filePath") or "").lower()
            snippet = (f.get("secretSnippet") or "").lower()
            return q in det or q in repo or q in fp or q in snippet
        findings = [f for f in findings if _matches(f)]

    total = len(findings)
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    page_items = findings[start:start + per_page]

    items = [
        SecretFinding(
            id=str(f.get("secretIdentity") or f.get("fingerprint") or ""),
            state=f.get("state", ""),
            review_status=f.get("reviewStatus", "new"),
            detector=f.get("detector", ""),
            file_path=f.get("filePath") or f.get("file_path") or "",
            line=f.get("line"),
            repository=f.get("repository", ""),
            organization=f.get("organization", ""),
            commit=f.get("commit"),
            secret_snippet=f.get("secretSnippet"),
            first_seen_at=f.get("first_seen_at") or f.get("detectedAt"),
            dismissed_at=f.get("dismissed_at"),
            dismissed_by=f.get("dismissed_by"),
            dismissed_reason=f.get("dismissed_reason"),
            # New fields
            secret_identity=f.get("secretIdentity"),
            fingerprint=f.get("fingerprint"),
            source=f.get("source", ""),
            classification_history=[
                ClassificationEntry(
                    value=e.get("value", ""),
                    source=e.get("source", ""),
                    scan_depth=e.get("scanDepth"),
                    confidence=e.get("confidence"),
                    run_id=e.get("runId"),
                    scanned_at=e.get("scannedAt"),
                )
                for e in (f.get("classificationHistory") or [])[-5:]  # cap at last 5
            ],
            risk_score=f.get("riskScore"),
            occurrence_count=f.get("occurrenceCount"),
            confirmed_at=f.get("confirmedAt"),
            resolved_at=f.get("resolvedAt"),
            detected_at=f.get("detectedAt"),
        )
        for f in page_items
    ]

    return SecretFindingsConnection(
        items=items,
        total_count=total,
        page_info=PageInfo(
            has_next_page=page < total_pages,
            has_previous_page=page > 1,
            total_pages=total_pages,
        ),
    )


def secrets_overview(org: str, info_context: dict[str, Any]) -> SecretsOverview:
    from datetime import datetime, timezone
    from src.secrets.service_analytics import compute_remediation_metrics, compute_repository_coverage

    findings = _load_scoped_findings(org, info_context)
    now = datetime.now(timezone.utc)

    unique_keys: set[str] = set()
    for f in findings:
        key = f.get("secretIdentity") or f.get("fingerprint") or ""
        if key:
            unique_keys.add(key)

    new_count = sum(1 for f in findings if f.get("reviewStatus") == "new")
    confirmed_count = sum(1 for f in findings if f.get("reviewStatus") == "confirmed")
    false_positive_count = sum(1 for f in findings if f.get("reviewStatus") == "false_positive")
    action_taken_count = sum(1 for f in findings if f.get("reviewStatus") == "action_taken")

    source_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("source", "unknown")
        source_counts[s] = source_counts.get(s, 0) + 1
    source_breakdown = sorted(
        [SourceCount(source=s, count=c) for s, c in source_counts.items()],
        key=lambda x: x.count, reverse=True,
    )

    # Remediation & coverage (count only git repos, not container images)
    from src.shared.config import get_scan_sources_for_org
    rem = compute_remediation_metrics(findings)
    sources = get_scan_sources_for_org(org)
    total_repos = len({url for s in sources for url in s.repo_urls})
    affected_repos = {
        str(f.get("repository") or "").lower()
        for f in findings
        if f.get("reviewStatus") not in ("false_positive", "action_taken")
        and str(f.get("repository") or "").strip()
    }
    affected_count = len(affected_repos)
    cov = {
        "affected": affected_count,
        "unaffected": max(0, total_repos - affected_count),
        "percentage": round((affected_count / total_repos) * 100) if total_repos else 0,
    }

    # Stale: confirmed and unresolved >30 days
    stale = 0
    for f in findings:
        if f.get("reviewStatus") != "confirmed":
            continue
        detected = f.get("detectedAt") or f.get("firstSeenAt")
        if detected:
            try:
                dt = _parse_dt(str(detected))
                if (now - dt).days > 30:
                    stale += 1
            except (ValueError, TypeError):
                pass

    # Resolved recently: action_taken in last 30 days
    resolved_recently = 0
    for f in findings:
        if f.get("reviewStatus") != "action_taken":
            continue
        resolved = f.get("resolvedAt") or f.get("dismissedAt")
        if resolved:
            try:
                dt = _parse_dt(str(resolved))
                if (now - dt).days <= 30:
                    resolved_recently += 1
            except (ValueError, TypeError):
                pass

    # Age buckets (unresolved = new + confirmed)
    bucket_defs = [
        ("< 7d", 0, 7), ("7–30d", 7, 30), ("1–3mo", 30, 90),
        ("3–6mo", 90, 180), ("6mo+", 180, float("inf")),
    ]
    unresolved = [f for f in findings if f.get("reviewStatus") in ("new", "confirmed")]
    bucket_counts = {label: 0 for label, _, _ in bucket_defs}
    for f in unresolved:
        detected = f.get("detectedAt") or f.get("firstSeenAt")
        if not detected:
            continue
        try:
            dt = _parse_dt(str(detected))
            days = max(0, (now - dt).total_seconds() / 86400)
            for label, lo, hi in bucket_defs:
                if lo <= days < hi:
                    bucket_counts[label] += 1
                    break
        except (ValueError, TypeError):
            pass

    # Triage priority: top repos by confirmed keys
    repo_stats: dict[str, dict[str, int]] = {}
    for f in findings:
        repo = f.get("repository", "")
        org_name = f.get("organization", "")
        if not repo:
            continue
        key = f"{org_name}/{repo}"
        if key not in repo_stats:
            repo_stats[key] = {"new": 0, "confirmed": 0}
        status = f.get("reviewStatus")
        if status == "new":
            repo_stats[key]["new"] += 1
        elif status == "confirmed":
            repo_stats[key]["confirmed"] += 1
    triage = sorted(
        [
            SecretsRepoPriority(
                organization=k.split("/", 1)[0] if "/" in k else "",
                repository=k.split("/", 1)[1] if "/" in k else k,
                unreviewed_count=v["new"],
                confirmed_count=v["confirmed"],
            )
            for k, v in repo_stats.items()
            if v["confirmed"] > 0
        ],
        key=lambda x: x.confirmed_count, reverse=True,
    )[:10]

    return SecretsOverview(
        unique_key_count=len(unique_keys),
        total_findings_count=len(findings),
        review_funnel=ReviewFunnel(
            new_count=new_count,
            confirmed_count=confirmed_count,
            false_positive_count=false_positive_count,
            action_taken_count=action_taken_count,
        ),
        source_breakdown=source_breakdown,
        remediation=RemediationStats(
            total_fixed=rem.get("totalFixed", 0),
            avg_days=rem.get("avgDays"),
            median_days=rem.get("medianDays"),
            fixed_last_30d=rem.get("fixedLast30d", 0),
        ),
        repository_coverage=CoverageStats(
            total=cov.get("affected", 0) + cov.get("unaffected", 0),
            affected=cov.get("affected", 0),
            unaffected=cov.get("unaffected", 0),
            percentage=cov.get("percentage", 0),
        ),
        stale_findings_count=stale,
        resolved_recently_count=resolved_recently,
        unresolved_count=len(unresolved),
        age_buckets=[AgeBucket(label=label, count=bucket_counts[label]) for label, _, _ in bucket_defs],
        triage_priority=triage,
    )


def secrets_filter_options(org: str, info_context: dict[str, Any]) -> SecretsFilterOptions:
    findings = _load_scoped_findings(org, info_context)
    organizations = sorted({f.get("organization", "") for f in findings if f.get("organization")})
    repositories = sorted({f.get("repository", "") for f in findings if f.get("repository")})
    detectors = sorted({f.get("detector", "") for f in findings if f.get("detector")})
    sources = sorted({f.get("source", "") for f in findings if f.get("source")})
    return SecretsFilterOptions(
        organizations=organizations,
        repositories=repositories,
        detectors=detectors,
        sources=sources,
    )

"""GraphQL resolvers for Code Scanning (Static Application Security Testing)."""
from __future__ import annotations

import math
from typing import Any, Optional

import strawberry

from src.graphql.auth import validate_org_access, GraphQLAuthError
from src.graphql.limits import clamp_per_page
from src.graphql.types import (
    SeverityCounts, SeverityBucket, AgeBucket, RepoSummary,
    RemediationStats, CoverageStats, RiskScore, PageInfo,
    CodeScanningRuleCount, StateBreakdown, CategoryCount, CodeScanningFilterOptions,
)
from src.storage import read_code_scanning_findings
from src.shared.analytics import build_analytics, get_counts
from src.shared.config import get_scan_sources_for_org
from src.shared.paths import parse_iso_utc as _parse_dt


def _git_repos_only(sources: list) -> list[dict[str, Any]]:
    """Extract only git repos (not container images) from scan sources."""
    repos: dict[str, dict[str, Any]] = {}
    for s in sources:
        for url in s.repo_urls:
            parts = url.rstrip("/").removesuffix(".git").split("/")[-2:]
            full_name = "/".join(parts)
            if full_name not in repos:
                repos[full_name] = {"full_name": full_name, "name": parts[-1]}
    return list(repos.values())


@strawberry.type
class CodeScanningAiReview:
    verdict: str
    explanation: str
    reasoning: Optional[str] = None
    confidence: Optional[str] = None


@strawberry.type
class CodeScanningCodeFlow:
    file: str
    line: int
    snippet: str


@strawberry.type
class CodeScanningCallChainStep:
    function: str
    file: str
    line: int
    snippet: Optional[str] = None


@strawberry.type
class CodeScanningReachability:
    verdict: str
    entry_point: Optional[str] = None
    call_chain: Optional[list[CodeScanningCallChainStep]] = None


def _make_ai_review(r: dict | None) -> Optional["CodeScanningAiReview"]:
    if not r:
        return None
    return CodeScanningAiReview(
        verdict=r.get("verdict", ""),
        explanation=r.get("explanation", ""),
        reasoning=r.get("reasoning"),
        confidence=r.get("confidence"),
    )


def _make_code_flows(flows: list | None) -> Optional[list["CodeScanningCodeFlow"]]:
    if not flows:
        return None
    return [
        CodeScanningCodeFlow(
            file=flow.get("file", ""),
            line=flow.get("line") or 0,
            snippet=flow.get("snippet", ""),
        )
        for flow in flows
    ]


def _make_reachability(r: dict | None) -> Optional["CodeScanningReachability"]:
    if not r:
        return None
    chain_raw = r.get("call_chain")
    call_chain = (
        [
            CodeScanningCallChainStep(
                function=step.get("function", ""),
                file=step.get("file", ""),
                line=step.get("line") or 0,
                snippet=step.get("snippet") or None,
            )
            for step in chain_raw
            if isinstance(step, dict)
        ]
        if isinstance(chain_raw, list)
        else None
    )
    return CodeScanningReachability(
        verdict=r.get("verdict", ""),
        entry_point=r.get("entry_point"),
        call_chain=call_chain,
    )


@strawberry.type
class CodeScanningFinding:
    id: str
    state: str
    severity: str
    rule_id: str
    rule_name: str
    message: str
    file_path: str
    line: int
    repo_full_name: str
    first_seen_at: Optional[str]
    fixed_at: Optional[str]
    language: Optional[str]
    confidence: Optional[str]
    category: Optional[str] = None
    cwe: Optional[list[str]] = None
    snippet: Optional[str] = None
    fix_suggestion: Optional[str] = None
    code_window: Optional[str] = None
    ai_review: Optional[CodeScanningAiReview] = None
    code_flows: Optional[list[CodeScanningCodeFlow]] = None
    reachability: Optional[CodeScanningReachability] = None
    # Commit attribution (§5.6)
    introduced_by_commit_sha: Optional[str] = None
    introduced_by_author: Optional[str] = None
    introduced_at: Optional[str] = None
    introduced_by_pr_url: Optional[str] = None


@strawberry.type
class CodeScanningFindingsConnection:
    items: list[CodeScanningFinding]
    total_count: int
    page_info: PageInfo


@strawberry.type
class CodeScanningAnalytics:
    counts: SeverityCounts
    severity_distribution: list[SeverityBucket]
    age_buckets: list[AgeBucket]
    top_repositories: list[RepoSummary]
    remediation: RemediationStats
    repository_coverage: CoverageStats
    risk_score: RiskScore
    # Code scanning-specific
    top_rules: list[CodeScanningRuleCount]
    awaiting_fix_count: int
    state_breakdown: StateBreakdown
    category_breakdown: list[CategoryCount]


def _extract_code_scanning_full_name(f: dict) -> str:
    # Code scanning uses repo_full_name, not repository.full_name
    return f.get("repo_full_name", "")


def _load_scoped_findings(org: str, ctx: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Load code scanning findings with per-request caching and repo-level scope filtering."""
    if not ctx:
        raise GraphQLAuthError("Unauthorized")
    orgs = [o.strip() for o in org.split(",") if o.strip()] or [org]
    for single_org in orgs:
        validate_org_access(ctx, single_org)
    request_cache = ctx.get("_cache")
    request = ctx.get("request")
    all_findings: list[dict[str, Any]] = []
    for single_org in orgs:
        cache_key = f"_code_scanning_findings:{single_org}"
        if request_cache is not None and cache_key in request_cache:
            all_findings.extend(request_cache[cache_key])
            continue
        findings = read_code_scanning_findings(single_org) or []
        if request:
            from src.shared.router_helpers import filter_findings_by_scope
            findings = filter_findings_by_scope(request, findings, _extract_code_scanning_full_name)
        if request_cache is not None:
            request_cache[cache_key] = findings
        all_findings.extend(findings)
    return all_findings


def _get_code_scanning_counts(alerts: list[dict[str, Any]]) -> "SeverityCounts":
    """Count code scanning findings by severity (severity is directly on the finding dict)."""
    critical = high = medium = low = 0
    for f in alerts:
        sev = f.get("severity", "")
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        elif sev == "low":
            low += 1
    return SeverityCounts(
        total=len(alerts),
        critical=critical,
        high=high,
        medium=medium,
        low=low,
    )


def _code_scanning_finding_to_advisory_shape(f: dict[str, Any]) -> dict[str, Any]:
    """Wrap a code scanning finding in the security_advisory shape expected by build_analytics."""
    return {
        **f,
        "security_advisory": {"severity": f.get("severity", "")},
        "repository": {"full_name": f.get("repo_full_name", "")},
    }


def code_scanning_counts(org: str, info_context: dict[str, Any]) -> SeverityCounts:
    findings = _load_scoped_findings(org, info_context)
    open_findings = [f for f in findings if f.get("state") == "open"]
    return _get_code_scanning_counts(open_findings)


def code_scanning_findings(
    org: str,
    page: int = 1,
    per_page: int = 25,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    language: Optional[str] = None,
    reachability: Optional[str] = None,
    confidence: Optional[str] = None,
    rule_id: Optional[str] = None,
    repository: Optional[str] = None,
    age_bucket: Optional[str] = None,
    search: Optional[str] = None,
    new_since_last_scan: Optional[bool] = None,
    last_scan_date: Optional[str] = None,
    info_context: dict[str, Any] | None = None,
) -> CodeScanningFindingsConnection:
    per_page = clamp_per_page(per_page)
    search = (search or "")[:200]
    findings = _load_scoped_findings(org, info_context)

    if state:
        findings = [f for f in findings if f.get("state") == state]
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if language:
        findings = [f for f in findings if f.get("language") == language]
    if reachability:
        findings = [f for f in findings if (f.get("reachability") or {}).get("verdict") == reachability]
    if confidence:
        findings = [f for f in findings if f.get("confidence") == confidence]
    if rule_id:
        findings = [f for f in findings if f.get("rule_id") == rule_id]
    if repository:
        findings = [f for f in findings if f.get("repo_full_name") == repository]
    if age_bucket:
        import time
        from datetime import datetime, timezone
        normalized = age_bucket.replace("\u2013", "-")
        AGE_RANGES = {"< 7d": (0, 7), "7-30d": (7, 30), "1-3mo": (30, 90), "3-6mo": (90, 180), "6mo+": (180, 999999)}
        bounds = AGE_RANGES.get(normalized)
        if bounds:
            lo, hi = bounds
            now_s = time.time()
            def _age_days(f):
                ca = f.get("first_seen_at")
                if not ca:
                    return 0
                try:
                    return (now_s - _parse_dt(ca).timestamp()) / 86400
                except (ValueError, OSError):
                    return 0
            findings = [f for f in findings if lo <= _age_days(f) < hi]
    if new_since_last_scan and last_scan_date:
        findings = [f for f in findings if (f.get("first_seen_at") or "") >= last_scan_date]
    if search:
        q = search.lower()
        def _matches_search(f):
            rule_name = (f.get("rule_name") or "").lower()
            file_path = (f.get("file_path") or "").lower()
            message = (f.get("message") or "").lower()
            rid = (f.get("rule_id") or "").lower()
            return q in rule_name or q in file_path or q in message or q in rid
        findings = [f for f in findings if _matches_search(f)]

    total = len(findings)
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    page_items = findings[start:start + per_page]

    items = [
        CodeScanningFinding(
            id=f"{f.get('repo_full_name', '')}:{f.get('rule_id', '')}:{f.get('file_path', '')}:{f.get('start_line', 0)}",
            state=f.get("state", ""),
            severity=f.get("severity", ""),
            rule_id=f.get("rule_id", ""),
            rule_name=f.get("rule_name", ""),
            message=f.get("message", ""),
            file_path=f.get("file_path", ""),
            line=f.get("start_line") or f.get("line") or 0,
            repo_full_name=f.get("repo_full_name", ""),
            first_seen_at=f.get("first_seen_at"),
            fixed_at=f.get("fixed_at"),
            language=f.get("language"),
            confidence=f.get("confidence"),
            category=f.get("category") or None,
            cwe=f.get("cwe") or None,
            snippet=f.get("snippet") or None,
            fix_suggestion=f.get("fix_suggestion"),
            code_window=f.get("code_window"),
            ai_review=_make_ai_review(f.get("ai_review")),
            code_flows=_make_code_flows(f.get("code_flows")),
            reachability=_make_reachability(f.get("reachability")),
            introduced_by_commit_sha=f.get("introduced_by_commit_sha"),
            introduced_by_author=f.get("introduced_by_author"),
            introduced_at=f.get("introduced_at"),
            introduced_by_pr_url=f.get("introduced_by_pr_url"),
        )
        for f in page_items
    ]

    return CodeScanningFindingsConnection(
        items=items,
        total_count=total,
        page_info=PageInfo(
            has_next_page=page < total_pages,
            has_previous_page=page > 1,
            total_pages=total_pages,
        ),
    )


def code_scanning_analytics(org: str, info_context: dict[str, Any]) -> CodeScanningAnalytics:
    findings = _load_scoped_findings(org, info_context)
    open_findings = [f for f in findings if f.get("state") == "open"]
    fixed_findings = [f for f in findings if f.get("state") == "fixed"]

    # Wrap in advisory shape so build_analytics can read severity correctly
    open_shaped = [_code_scanning_finding_to_advisory_shape(f) for f in open_findings]
    fixed_shaped = [_code_scanning_finding_to_advisory_shape(f) for f in fixed_findings]

    orgs = [o.strip() for o in org.split(",") if o.strip()] or [org]
    seen_repos: dict[str, dict[str, Any]] = {}
    for single_org in orgs:
        for r in _git_repos_only(get_scan_sources_for_org(single_org)):
            seen_repos.setdefault(r["full_name"], r)
    source_repos = list(seen_repos.values())
    analytics = build_analytics(open_shaped, fixed_shaped, source_repos)

    # top_rules: group by rule_id, count, sort desc, take 10
    rule_counts: dict[str, dict] = {}
    for f in open_findings:
        rid = f.get("rule_id", "")
        if rid not in rule_counts:
            rule_counts[rid] = {"rule_id": rid, "rule_name": f.get("rule_name", ""), "count": 0}
        rule_counts[rid]["count"] += 1
    top_rules = sorted(rule_counts.values(), key=lambda x: x["count"], reverse=True)[:10]
    top_rules_typed = [CodeScanningRuleCount(**r) for r in top_rules]

    # awaiting_fix_count
    awaiting_fix_count = len([f for f in findings if f.get("state") == "awaiting_fix"])

    # state_breakdown
    state_breakdown = StateBreakdown(
        open=len([f for f in findings if f.get("state") == "open"]),
        dismissed=len([f for f in findings if f.get("state") == "dismissed"]),
        fixed=len([f for f in findings if f.get("state") == "fixed"]),
        awaiting_fix=awaiting_fix_count,
    )

    # category_breakdown
    cat_counts: dict[str, int] = {}
    for f in open_findings:
        cat = f.get("category", "")
        if cat:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
    category_breakdown = sorted(
        [CategoryCount(category=c, count=n) for c, n in cat_counts.items()],
        key=lambda x: x.count, reverse=True,
    )

    return CodeScanningAnalytics(
        counts=SeverityCounts(
            total=analytics.counts.total,
            critical=analytics.counts.critical,
            high=analytics.counts.high,
            medium=analytics.counts.medium,
            low=analytics.counts.low,
        ),
        severity_distribution=[
            SeverityBucket(severity=b.severity, count=b.count, percentage=b.percentage)
            for b in analytics.severityDistribution
        ],
        age_buckets=[AgeBucket(label=b.label, count=b.count) for b in analytics.ageBuckets],
        top_repositories=[
            RepoSummary(name=r.name, open=r.open, critical=r.critical, high=r.high)
            for r in analytics.topRepositories
        ],
        remediation=RemediationStats(
            total_fixed=analytics.remediation.totalFixed,
            avg_days=analytics.remediation.avgDays,
            median_days=analytics.remediation.medianDays,
            fixed_last_30d=analytics.remediation.fixedLast30d,
        ),
        repository_coverage=CoverageStats(
            total=analytics.repositoryCoverage.total,
            affected=analytics.repositoryCoverage.affected,
            unaffected=analytics.repositoryCoverage.unaffected,
            percentage=analytics.repositoryCoverage.percentage,
        ),
        risk_score=RiskScore(
            score=analytics.riskScore.score,
            rating=analytics.riskScore.rating,
            summary=analytics.riskScore.summary,
        ),
        top_rules=top_rules_typed,
        awaiting_fix_count=awaiting_fix_count,
        state_breakdown=state_breakdown,
        category_breakdown=category_breakdown,
    )


def code_scanning_filter_options(org: str, info_context: dict[str, Any]) -> CodeScanningFilterOptions:
    findings = _load_scoped_findings(org, info_context)
    repos = sorted({f.get("repo_full_name", "") for f in findings if f.get("repo_full_name")})
    languages = sorted({f.get("language", "") for f in findings if f.get("language")})
    rule_ids = sorted({f.get("rule_id", "") for f in findings if f.get("rule_id")})
    return CodeScanningFilterOptions(repositories=repos, languages=languages, rule_ids=rule_ids)

"""GraphQL resolvers for Dependencies (Dependency Scanning)."""
from __future__ import annotations

import math
from typing import Any, Optional

import strawberry

from src.graphql.auth import GraphQLAuthError
from src.graphql.limits import clamp_per_page
from src.graphql.types import (
    SeverityCounts, SeverityBucket, AgeBucket, RepoSummary,
    RemediationStats, CoverageStats, RiskScore, PageInfo,
    FilterOptions, MonthlyTrendItem, EcosystemBreakdownItem,
    VulnerablePackage, MTTRBySeverity, RemediationPriorityRow,
)
from src.storage import read_dependencies_findings
from src.shared.analytics import build_analytics, get_counts
from src.shared.config import get_scan_sources_for_org
from src.shared.home_views import get_severity_counts_by_asset_ids
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
class DependenciesFinding:
    id: str
    state: str
    severity: str
    ecosystem: str
    package_name: str
    vulnerable_version: str
    patched_version: Optional[str]
    repo_full_name: str
    advisory_summary: Optional[str]
    cvss_score: Optional[float]
    first_seen_at: Optional[str]
    fixed_at: Optional[str]
    current_version: Optional[str]
    manifest_path: Optional[str]
    ghsa_id: Optional[str]
    # Commit attribution (§5.6)
    introduced_by_commit_sha: Optional[str] = None
    introduced_by_author: Optional[str] = None
    introduced_at: Optional[str] = None
    introduced_by_pr_url: Optional[str] = None


@strawberry.type
class DependenciesFindingDetail:
    identity_key: str
    org: str
    state: str
    severity: str
    ecosystem: str
    package_name: str
    current_version: Optional[str]
    manifest_path: str
    ghsa_id: str
    cve_id: Optional[str]
    advisory_summary: Optional[str]
    advisory_description: str
    advisory_url: Optional[str]
    published_at: Optional[str]
    advisory_updated_at: Optional[str]
    references: list[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    vulnerable_version_range: str
    patched_version: Optional[str]
    manifest_snippet: Optional[str]
    manifest_match_line: Optional[int]
    first_seen_at: Optional[str]
    fixed_at: Optional[str]
    dismissed_reason: Optional[str]
    repo_full_name: str
    # Commit attribution (§5.6)
    introduced_by_commit_sha: Optional[str] = None
    introduced_by_author: Optional[str] = None
    introduced_at: Optional[str] = None
    introduced_by_pr_url: Optional[str] = None


@strawberry.type
class DependenciesFindingsConnection:
    items: list[DependenciesFinding]
    total_count: int
    page_info: PageInfo


@strawberry.type
class DependenciesAnalytics:
    counts: SeverityCounts
    severity_distribution: list[SeverityBucket]
    age_buckets: list[AgeBucket]
    top_repositories: list[RepoSummary]
    remediation: RemediationStats
    repository_coverage: CoverageStats
    risk_score: RiskScore
    monthly_trend: list[MonthlyTrendItem]
    ecosystem_breakdown: list[EcosystemBreakdownItem]
    top_vulnerable_packages: list[VulnerablePackage]
    mttr_by_severity: MTTRBySeverity
    remediation_priority: list[RemediationPriorityRow]
    stale_findings_count: int
    deferred_findings_count: int


def _load_scoped_findings(asset_ids: list[str], ctx: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Load findings with per-request caching, scoped by asset_ids."""
    if not ctx:
        raise GraphQLAuthError("Unauthorized")
    if not asset_ids:
        return []
    request_cache = ctx.get("_cache")
    cache_key = f"_dependencies_findings:asset_ids:{','.join(sorted(asset_ids))}"
    if request_cache is not None and cache_key in request_cache:
        return list(request_cache[cache_key])
    # asset_id IS the scope; no further per-repo filtering needed
    findings = read_dependencies_findings(asset_ids=asset_ids) or []
    if request_cache is not None:
        request_cache[cache_key] = findings
    return findings


def dependencies_counts(*, asset_ids: list[str], info_context: dict[str, Any]) -> SeverityCounts:
    counts = get_severity_counts_by_asset_ids(asset_ids, tool="dependencies", state="open")
    return SeverityCounts(
        total=counts["total"], critical=counts["critical"],
        high=counts["high"], medium=counts["medium"], low=counts["low"],
    )


def dependencies_findings(
    *,
    asset_ids: list[str],
    org: Optional[str] = None,
    page: int = 1,
    per_page: int = 25,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    ecosystem: Optional[list[str]] = None,
    repository: Optional[str] = None,
    organization: Optional[str] = None,
    package_search: Optional[str] = None,
    fix_availability: Optional[str] = None,
    cvss_range: Optional[str] = None,
    age_bucket: Optional[str] = None,
    search: Optional[str] = None,
    new_since_last_scan: Optional[bool] = None,
    last_scan_date: Optional[str] = None,
    info_context: dict[str, Any] | None = None,
) -> DependenciesFindingsConnection:
    if not asset_ids:
        return DependenciesFindingsConnection(
            items=[], total_count=0,
            page_info=PageInfo(has_next_page=False, has_previous_page=False, total_pages=0),
        )
    per_page = clamp_per_page(per_page)
    findings = _load_scoped_findings(asset_ids, info_context)
    # org is a UI filter to narrow the asset-scoped result to specific orgs
    if org:
        wanted = {o.strip().lower() for o in org.split(",") if o.strip()}
        findings = [f for f in findings if (f.get("repository") or {}).get("full_name", "").split("/")[0].lower() in wanted]

    # Input validation
    if ecosystem:
        ecosystem = ecosystem[:50]
    if search:
        search = search[:200]
    if package_search:
        package_search = package_search[:200]

    # Filters
    if state:
        findings = [f for f in findings if f.get("state") == state]
    if severity:
        findings = [f for f in findings if (f.get("security_advisory") or {}).get("severity") == severity]
    if ecosystem:
        findings = [f for f in findings if (f.get("dependency") or {}).get("package", {}).get("ecosystem", "") in ecosystem]
    if repository:
        findings = [f for f in findings if (f.get("repository") or {}).get("full_name") == repository or (f.get("repository") or {}).get("name") == repository]
    if organization:
        findings = [f for f in findings if (f.get("repository") or {}).get("full_name", "").split("/")[0] == organization]
    if package_search:
        q = package_search.lower()
        findings = [f for f in findings if q in ((f.get("dependency") or {}).get("package", {}).get("name", "")).lower()]
    if fix_availability == "has_fix":
        findings = [f for f in findings if (f.get("security_vulnerability") or {}).get("first_patched_version")]
    elif fix_availability == "no_fix":
        findings = [f for f in findings if not (f.get("security_vulnerability") or {}).get("first_patched_version")]
    if cvss_range:
        normalized = cvss_range.replace("\u2013", "-")
        CVSS_RANGES = {"9.0+": (9.0, 10.1), "7.0-8.9": (7.0, 9.0), "4.0-6.9": (4.0, 7.0), "0.1-3.9": (0.1, 4.0)}
        bounds = CVSS_RANGES.get(normalized)
        if bounds:
            lo, hi = bounds
            findings = [f for f in findings if lo <= ((f.get("security_advisory") or {}).get("cvss") or {}).get("score", 0) < hi]
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
                ca = f.get("created_at") or f.get("first_seen_at")
                if not ca:
                    return 0
                try:
                    return (now_s - _parse_dt(ca).timestamp()) / 86400
                except (ValueError, OSError):
                    return 0
            findings = [f for f in findings if lo <= _age_days(f) < hi]
    if new_since_last_scan and last_scan_date:
        findings = [f for f in findings if (f.get("first_seen_at") or f.get("created_at") or "") >= last_scan_date]
    if search:
        q = search.lower()
        def _matches_search(f):
            pkg = ((f.get("dependency") or {}).get("package", {}).get("name", "")).lower()
            repo_name = ((f.get("repository") or {}).get("name", "")).lower()
            cve = ((f.get("security_advisory") or {}).get("cve_id") or "").lower()
            ghsa = ((f.get("security_advisory") or {}).get("ghsa_id") or "").lower()
            return q in pkg or q in repo_name or q in cve or q in ghsa
        findings = [f for f in findings if _matches_search(f)]

    total = len(findings)
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    page_items = findings[start:start + per_page]

    items = []
    for f in page_items:
        adv = f.get("security_advisory") or {}
        vuln = f.get("security_vulnerability") or {}
        dep = f.get("dependency") or {}
        repo = f.get("repository") or {}
        items.append(DependenciesFinding(
            id=f"{repo.get('full_name', '')}:{adv.get('ghsa_id') or adv.get('cve_id') or ''}:{(vuln.get('package') or {}).get('name', '')}",
            state=f.get("state", ""),
            severity=adv.get("severity", ""),
            ecosystem=(dep.get("package") or {}).get("ecosystem", ""),
            package_name=(vuln.get("package") or {}).get("name", ""),
            vulnerable_version=vuln.get("vulnerable_version_range", ""),
            patched_version=(vuln.get("first_patched_version") or {}).get("identifier") if isinstance(vuln.get("first_patched_version"), dict) else vuln.get("first_patched_version"),
            repo_full_name=repo.get("full_name", ""),
            advisory_summary=adv.get("summary"),
            cvss_score=(adv.get("cvss") or {}).get("score") if isinstance(adv.get("cvss"), dict) else adv.get("cvss_score"),
            first_seen_at=f.get("created_at"),
            fixed_at=f.get("fixed_at"),
            current_version=f.get("current_version"),
            manifest_path=(dep.get("manifest_path") or None),
            ghsa_id=adv.get("ghsa_id") or None,
            introduced_by_commit_sha=f.get("introduced_by_commit_sha"),
            introduced_by_author=f.get("introduced_by_author"),
            introduced_at=f.get("introduced_at"),
            introduced_by_pr_url=f.get("introduced_by_pr_url"),
        ))

    return DependenciesFindingsConnection(
        items=items,
        total_count=total,
        page_info=PageInfo(
            has_next_page=page < total_pages,
            has_previous_page=page > 1,
            total_pages=total_pages,
        ),
    )


def dependencies_finding_detail(
    *,
    asset_ids: list[str],
    org: Optional[str] = None,
    identity_key: str,
    info_context: dict[str, Any] | None,
) -> Optional[DependenciesFindingDetail]:
    if not info_context:
        raise GraphQLAuthError("Unauthorized")

    from src.db.helpers import run_db
    from src.shared.finding_queries import read_dependency_finding_detail_by_key
    from src.storage import _finding_to_dependencies_alert

    if not asset_ids:
        return None

    row = run_db(
        lambda session: read_dependency_finding_detail_by_key(
            session, asset_ids=asset_ids, identity_key=identity_key,
        )
    )
    if not row:
        return None

    f, decision, asset = row
    alert = _finding_to_dependencies_alert(f, decision, asset)

    advisory = alert.get("security_advisory") or {}
    vuln = alert.get("security_vulnerability") or {}
    dep = alert.get("dependency") or {}

    pv = vuln.get("first_patched_version") or {}
    patched = pv.get("identifier") if isinstance(pv, dict) else pv or None

    from src.assets.refs import owner_from_external_ref
    try:
        org_value = owner_from_external_ref(asset.external_ref)
    except ValueError:
        org_value = ""
    return DependenciesFindingDetail(
        identity_key=f.identity_key,
        org=org_value,
        state=alert["state"],
        severity=f.severity or "",
        ecosystem=(dep.get("package") or {}).get("ecosystem", ""),
        package_name=(dep.get("package") or {}).get("name", ""),
        current_version=alert.get("current_version"),
        manifest_path=dep.get("manifest_path", ""),
        ghsa_id=advisory.get("ghsa_id", ""),
        cve_id=advisory.get("cve_id"),
        advisory_summary=advisory.get("summary") or None,
        advisory_description=advisory.get("description", ""),
        advisory_url=advisory.get("html_url") or None,
        published_at=advisory.get("published_at") or None,
        advisory_updated_at=advisory.get("updated_at") or None,
        references=[
            r["url"] for r in advisory.get("references", [])
            if isinstance(r, dict) and r.get("url")
        ],
        cvss_score=(advisory.get("cvss") or {}).get("score"),
        cvss_vector=(advisory.get("cvss") or {}).get("vector_string"),
        vulnerable_version_range=vuln.get("vulnerable_version_range", ""),
        patched_version=patched,
        manifest_snippet=alert.get("manifest_snippet"),
        manifest_match_line=alert.get("manifest_match_line"),
        first_seen_at=alert.get("first_seen_at"),
        fixed_at=alert.get("fixed_at"),
        dismissed_reason=alert.get("dismissed_reason"),
        repo_full_name=(alert.get("repository") or {}).get("full_name", ""),
        introduced_by_commit_sha=alert.get("introduced_by_commit_sha"),
        introduced_by_author=alert.get("introduced_by_author"),
        introduced_at=alert.get("introduced_at"),
        introduced_by_pr_url=alert.get("introduced_by_pr_url"),
    )


def dependencies_filter_options(*, asset_ids: list[str], org: Optional[str] = None, info_context: dict[str, Any]) -> FilterOptions:
    findings = _load_scoped_findings(asset_ids, info_context)
    ecosystems = sorted({
        (f.get("dependency") or {}).get("package", {}).get("ecosystem", "")
        for f in findings if (f.get("dependency") or {}).get("package", {}).get("ecosystem")
    })
    # Derive repo/org lists from Asset.external_ref (Finding.org/repo dropped in Plan D)
    repos, orgs = _scoped_repos_and_orgs(asset_ids)
    return FilterOptions(ecosystems=ecosystems, repositories=repos, organizations=orgs)


def _scoped_repos_and_orgs(asset_ids: list[str]) -> tuple[list[str], list[str]]:
    """Return (repos, orgs) lists derived from Asset.external_ref for the given assets."""
    if not asset_ids:
        return [], []
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import Asset
    from src.assets.refs import owner_from_external_ref

    async def _query(session):
        rows = (await session.execute(
            select(Asset.external_ref).where(Asset.id.in_(asset_ids), Asset.type == "repo")
        )).scalars().all()
        return list(rows)

    refs = run_db(_query)
    repos: set[str] = set()
    orgs: set[str] = set()
    for ref in refs:
        try:
            owner = owner_from_external_ref(ref)
        except ValueError:
            continue
        # ref format: "github:acme/foo" → repo full_name = "acme/foo"
        rest = ref.split(":", 1)[1]
        repos.add(rest)
        orgs.add(owner)
    return sorted(repos), sorted(orgs)


def _compute_monthly_trend(findings: list[dict]) -> list[MonthlyTrendItem]:
    if not findings:
        return []
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    dates = []
    for f in findings:
        ca = f.get("created_at") or f.get("first_seen_at")
        if ca:
            try:
                dates.append(_parse_dt(ca))
            except (ValueError, OSError):
                pass
    if not dates:
        return []
    min_date = min(dates)
    months = []
    cy, cm = min_date.year, min_date.month
    while (cy, cm) <= (now.year, now.month):
        months.append(f"{cy}-{cm:02d}")
        cm += 1
        if cm > 12:
            cm = 1
            cy += 1
    result = []
    for ms in months:
        y, m = int(ms[:4]), int(ms[5:7])
        start = datetime(y, m, 1, tzinfo=timezone.utc)
        em = m + 1 if m < 12 else 1
        ey = y if m < 12 else y + 1
        end = datetime(ey, em, 1, tzinfo=timezone.utc)
        introduced = resolved = open_at_end = 0
        for f in findings:
            ca = f.get("created_at") or f.get("first_seen_at") or ""
            fa = f.get("fixed_at")
            da = f.get("dismissed_at")
            try:
                ct = _parse_dt(ca)
            except (ValueError, OSError):
                continue
            if start <= ct < end:
                introduced += 1
            if fa:
                try:
                    ft = _parse_dt(fa)
                    if start <= ft < end:
                        resolved += 1
                except (ValueError, OSError):
                    pass
            if ct < end:
                if f.get("state") != "open":
                    closed_at = fa or da
                    if closed_at:
                        try:
                            clt = _parse_dt(closed_at)
                            if clt < end:
                                continue
                        except (ValueError, OSError):
                            pass
                open_at_end += 1
        result.append(MonthlyTrendItem(month=ms, introduced=introduced, resolved=resolved, open_at_end=open_at_end))
    return result


def _compute_ecosystem_breakdown(findings: list[dict]) -> list[EcosystemBreakdownItem]:
    open_findings = [f for f in findings if f.get("state") == "open"]
    eco_map: dict[str, dict[str, int]] = {}
    for f in open_findings:
        eco = (f.get("dependency") or {}).get("package", {}).get("ecosystem", "").lower()
        if not eco:
            continue
        sev = (f.get("security_advisory") or {}).get("severity", "low")
        if eco not in eco_map:
            eco_map[eco] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        if sev in eco_map[eco]:
            eco_map[eco][sev] += 1
        eco_map[eco]["total"] += 1
    return sorted(
        [EcosystemBreakdownItem(ecosystem=eco, **counts) for eco, counts in eco_map.items()],
        key=lambda x: x.total, reverse=True,
    )


def _compute_top_vulnerable_packages(findings: list[dict], limit: int = 10) -> list[VulnerablePackage]:
    open_findings = [f for f in findings if f.get("state") == "open"]
    pkg_map: dict[str, dict] = {}
    for f in open_findings:
        dep = (f.get("dependency") or {}).get("package", {})
        name = dep.get("name", "")
        eco = dep.get("ecosystem", "")
        key = f"{eco}::{name}"
        if key not in pkg_map:
            pkg_map[key] = {"name": name, "ecosystem": eco, "repo_count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        pkg_map[key]["repo_count"] += 1
        sev = (f.get("security_advisory") or {}).get("severity", "low")
        if sev in pkg_map[key]:
            pkg_map[key][sev] += 1
    return sorted(
        [VulnerablePackage(**p) for p in pkg_map.values()],
        key=lambda x: x.repo_count, reverse=True,
    )[:limit]


def _compute_mttr_by_severity(findings: list[dict]) -> MTTRBySeverity:
    from datetime import datetime, timezone
    def avg_days(sev: str) -> float | None:
        durations = []
        for f in findings:
            if not f.get("fixed_at"):
                continue
            if (f.get("security_advisory") or {}).get("severity") != sev:
                continue
            ca = f.get("created_at") or f.get("first_seen_at")
            if not ca:
                continue
            try:
                ct = _parse_dt(ca).timestamp()
                ft = _parse_dt(f["fixed_at"]).timestamp()
                d = (ft - ct) / 86400
                if d >= 0:
                    durations.append(d)
            except (ValueError, OSError):
                pass
        return round(sum(durations) / len(durations), 1) if durations else None
    return MTTRBySeverity(critical=avg_days("critical"), high=avg_days("high"), medium=avg_days("medium"), low=avg_days("low"))


def _compute_remediation_priority(findings: list[dict], limit: int = 20) -> list[RemediationPriorityRow]:
    open_findings = [f for f in findings if f.get("state") == "open"]
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    seen: dict[str, dict] = {}
    for f in open_findings:
        adv = f.get("security_advisory") or {}
        dep = (f.get("dependency") or {}).get("package", {})
        vuln = f.get("security_vulnerability") or {}
        ghsa = adv.get("ghsa_id", "")
        pkg = dep.get("name", "")
        key = f"{ghsa}::{pkg}"
        if key not in seen:
            seen[key] = {
                "package_name": pkg, "ecosystem": dep.get("ecosystem", ""),
                "ghsa_id": ghsa, "cve_id": adv.get("cve_id"),
                "severity": adv.get("severity", "low"),
                "repos_affected": 0,
                "patch_version": (vuln.get("first_patched_version") or {}).get("identifier") if isinstance(vuln.get("first_patched_version"), dict) else vuln.get("first_patched_version"),
                "advisory_url": adv.get("html_url", ""),
            }
        seen[key]["repos_affected"] += 1
    rows = sorted(seen.values(), key=lambda x: (SEV_ORDER.get(x["severity"], 9), -x["repos_affected"]))
    return [RemediationPriorityRow(rank=i + 1, **r) for i, r in enumerate(rows[:limit])]


def dependencies_analytics(*, asset_ids: list[str], org: Optional[str] = None, info_context: dict[str, Any]) -> DependenciesAnalytics:
    findings = _load_scoped_findings(asset_ids, info_context)
    if org:
        wanted = {o.strip().lower() for o in org.split(",") if o.strip()}
        findings = [f for f in findings if (f.get("repository") or {}).get("full_name", "").split("/")[0].lower() in wanted]
    open_findings = [f for f in findings if f.get("state") == "open"]
    fixed_findings = [f for f in findings if f.get("state") == "fixed"]

    # Derive unique orgs from findings for coverage computation
    orgs = sorted({(f.get("repository") or {}).get("full_name", "").split("/")[0] for f in findings if (f.get("repository") or {}).get("full_name", "").count("/") >= 1})
    seen_repos: dict[str, dict[str, Any]] = {}
    for single_org in orgs:
        for r in _git_repos_only(get_scan_sources_for_org(single_org)):
            seen_repos.setdefault(r["full_name"], r)
    source_repos = list(seen_repos.values())
    analytics = build_analytics(open_findings, fixed_findings, source_repos)

    import time
    from datetime import datetime, timezone
    now_s = time.time()
    stale = 0
    deferred = len([f for f in findings if f.get("state") == "deferred"])
    for f in open_findings:
        ca = f.get("created_at") or f.get("first_seen_at")
        if ca:
            try:
                age = (now_s - _parse_dt(ca).timestamp()) / 86400
                if age > 30:
                    stale += 1
            except (ValueError, OSError):
                pass

    return DependenciesAnalytics(
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
        monthly_trend=_compute_monthly_trend(findings),
        ecosystem_breakdown=_compute_ecosystem_breakdown(findings),
        top_vulnerable_packages=_compute_top_vulnerable_packages(findings),
        mttr_by_severity=_compute_mttr_by_severity(findings),
        remediation_priority=_compute_remediation_priority(findings),
        stale_findings_count=stale,
        deferred_findings_count=deferred,
    )

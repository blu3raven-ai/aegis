"""GraphQL resolvers for SBOM component search, history, and diff."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Optional, Union
from urllib.parse import unquote

import strawberry
from sqlalchemy import func, select, or_, and_, exists, desc, distinct, case

from src.db.helpers import run_db
from src.graphql.resolver_utils import raise_bad_input
from src.db.models import Asset, Finding, SbomComponent, Sbom, SbomRun
from src.assets.refs import owner_from_external_ref
from src.sbom.diff import diff_sboms
from src.sbom.search_query import (
    SearchQueryError,
    _escape_like,
    compile_query,
    parse_search_query,
)
from src.sbom.diff_overlay import DiffOverlay, compute_diff_overlay
from src.sbom.licenses import category_rank, classify_licenses
from src.sbom.range_match import declared_range_admits
from src.shared.object_store import download_json
from src.sbom.storage import download_from_minio

from src.graphql.limits import clamp_per_page

logger = logging.getLogger(__name__)

MAX_BULK_ITEMS = 500

# Semver comparison runs in Python (string ordering is wrong for versions), so
# cap how many candidate rows the version filter pulls into memory. The base
# filters (search/ecosystem/repo/scope) usually narrow well below this; the cap
# is a safety valve against an unbounded fetch on a very large estate.
_MAX_VERSION_SCAN = 25000

# Bulk lookup batches every input into one query; this is a global, name-ordered
# row budget so a pasted list matching ubiquitous packages can't fetch an
# unbounded set. On a very large estate that exceeds the cap, alphabetically
# later queries may be truncated — the resolver logs a warning when it hits it.
_MAX_BULK_ROWS = MAX_BULK_ITEMS * 100

# Per-query occurrence cap. The match stays "found"; the frontend renders a
# "+N more" affordance off the total it can derive from the bucketing.
_MAX_BULK_OCCURRENCES = 50


def _parse_bulk_query(q: str) -> tuple[str, Optional[str], Optional[str]]:
    """Split a bulk-lookup query into ``(match_query, ecosystem, flagged_version)``.

    ``match_query`` is the version-stripped string fed to the existing matching
    path (a ``pkg:`` query stays a versionless purl, a plain query stays a name).
    ``ecosystem`` is informational only (lower-cased, derived from a purl) and is
    never used to filter — PyPI/pypi-style normalization across tools is too
    lossy to gate on. ``flagged_version`` is the version the caller pinned, or
    None.

    Version detection uses ``rfind('@')`` and only treats it as a separator when
    the ``@`` is not at index 0, so an npm scope (``@angular/core``) is preserved
    while ``@angular/core@13.0.0`` splits on the trailing version.
    """
    s = q.strip()
    if not s:
        return "", None, None

    if s.startswith("pkg:"):
        # Qualifiers (?a=b) and subpath (#frag) sit after the version, so strip
        # them before locating the '@'.
        core = s.split("?", 1)[0].split("#", 1)[0]
        after = core[len("pkg:"):]
        ecosystem = (after.split("/", 1)[0] or "").lower() or None
        at = core.rfind("@")
        if at > 0:
            return core[:at], ecosystem, (core[at + 1:] or None)
        return core, ecosystem, None

    at = s.rfind("@")
    if at > 0:
        return s[:at], None, (s[at + 1:] or None)
    return s, None, None


def _purl_name(match_query: str) -> str:
    """Derive a lower-cased package name from a versionless purl so a stored,
    *versioned* purl (the common case) can still be reached via the name index."""
    rest = match_query[len("pkg:"):]
    path = rest.split("/", 1)[1] if "/" in rest else ""
    return unquote(path).lower()

# Cross-reference returns one row per in-scope asset carrying a PURL; a package
# in every repo would otherwise serialize a node per asset. Cap the fan-out.
_MAX_CROSS_REFS = 500

# A container-image diff can change thousands of OS packages; cap how many node
# objects each diff bucket serializes (the OSV re-match overlay is separately
# capped). True totals are reported alongside so the count stays honest.
_MAX_DIFF_NODES = 1000


def _safe_owner_from_ref(external_ref: str | None) -> str:
    """Return owner segment of external_ref, or empty string on failure.

    Used at GraphQL response time where raising on an unrecognized ref
    would break a paginated list response.
    """
    if not external_ref:
        return ""
    try:
        return owner_from_external_ref(external_ref)
    except ValueError:
        return ""


@strawberry.type
class ComponentVulnCounts:
    """Open findings mapped to a component, bucketed by severity. Counts come
    from a scoped join on (asset_id, package_name) against open findings."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


def _zero_vuln_counts() -> dict[str, int]:
    """A fresh mutable severity-bucket accumulator."""
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}


@strawberry.type
class RepoComponentVulns:
    """Open-finding severity counts for one package *version* within a single
    repo, so the client can overlay counts onto the exact (name, version) row of
    its parsed SBOM. ``package_version`` is null for findings whose source didn't
    resolve a version — those apply to every version of the name (name-level)."""
    package_name: str
    package_version: Optional[str]
    vulns: ComponentVulnCounts


@strawberry.type
class SbomComponentNode:
    name: str
    version: str
    ecosystem: str
    purl: str
    repo: str
    org: str
    source_tool: Optional[str]
    scanned_at: str
    is_container: bool = False
    vulns: ComponentVulnCounts = strawberry.field(default_factory=ComponentVulnCounts)
    # Normalized SPDX string + risk category (classified at ingest).
    license: Optional[str] = None
    license_category: Optional[str] = None
    # Tri-state origin: True=direct, False=transitive, None=unknown.
    is_direct: Optional[bool] = None


@strawberry.type
class SbomComponentsConnection:
    items: list[SbomComponentNode]
    total: int
    page: int
    per_page: int
    total_pages: int
    # True when a version filter scanned more rows than the cap, so ``total``
    # and the page reflect only the first ``_MAX_VERSION_SCAN`` (name-ordered)
    # components — the client should surface "incomplete" rather than treat the
    # count as authoritative.
    truncated: bool = False


@strawberry.type
class RiskyComponent:
    """A package ranked by estate-wide open-vuln risk: severity-bucketed open
    findings plus the number of distinct assets it appears in (blast radius).

    ``license``/``license_category`` carry the package's worst-case license risk
    across the estate (the most-restrictive category seen on any in-scope
    component for this name), so a high-blast-radius package that is also
    copyleft is visible without leaving the risk view."""
    package_name: str
    ecosystem: str
    repo_count: int
    vulns: ComponentVulnCounts
    license: Optional[str] = None
    license_category: Optional[str] = None


@strawberry.type
class RiskyComponentsConnection:
    items: list[RiskyComponent]
    total: int
    page: int
    per_page: int
    total_pages: int


@strawberry.type
class SbomEcosystemAnalytics:
    """SBOM analytics aggregated at the ecosystem level.

    Shows for each ecosystem:
    - Finding counts by severity
    - Component count
    - Coverage metrics (assets with components/total assets)
    - Risk score
    """
    ecosystem: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total_findings: int = 0
    total_components: int = 0
    assets_with_components: int = 0
    assets_with_findings: int = 0
    coverage_percentage: float = 0.0
    risk_score: int = 0


@strawberry.type
class PackageRepo:
    """One asset (repo or container image) affected by a package's open
    vulnerabilities, with the per-asset severity breakdown — the "where used"
    detail behind a risky package's blast-radius count."""
    repo: str
    org: str
    is_container: bool
    vulns: ComponentVulnCounts


@strawberry.type
class SbomFilterOptions:
    ecosystems: list[str]
    repositories: list[str]
    sources: list[str]
    license_categories: list[str]
    dependency_scopes: list[str]


@strawberry.type
class SbomCrossReference:
    repo: str
    org: str
    version: str
    source_tool: Optional[str]
    scanned_at: str
    is_container: bool = False
    # Per-occurrence license risk: a package can carry a stricter licence in one
    # repo than another, so the badge reflects this row's component, not a roll-up.
    license: Optional[str] = None
    license_category: Optional[str] = None


@strawberry.type
class SbomBulkOccurrence:
    """One repo/version pair where a queried package appears. ``flagged`` marks
    the version the caller pinned in the query (``name@version``). ``latent``
    marks a repo not on the flagged version whose declared dependency range
    still admits it — a clean reinstall could pull the flagged version in."""
    repo: str
    version: str
    flagged: bool
    latent: bool = False


@strawberry.type
class SbomBulkMatch:
    query: str
    found: bool
    name: str
    ecosystem: str
    purl: str
    # Version parsed from the query (``name@version``), or None when unpinned.
    queried_version: Optional[str]
    # Exposure bucket: "flagged_in_use" | "other_versions" | "present" | "not_found".
    exposure: str
    occurrences: list[SbomBulkOccurrence]
    # True occurrence count before the per-query cap, so the UI shows the real
    # blast radius ("+N more") instead of a figure bounded by the cap.
    occurrence_total: int = 0
    occurrences_truncated: bool = False
    # Worst-case license across the matched occurrences (most-restrictive
    # category wins), so a copyleft copy anywhere in the estate is surfaced.
    license: Optional[str] = None
    license_category: Optional[str] = None


@strawberry.type
class SbomCrossRefResult:
    """Cross-reference rows plus an honest signal that the server capped them.

    ``truncated`` is true when more in-scope rows exist than ``cap``, so the UI
    can show "N+" instead of letting a capped list read as the complete set.
    """
    items: list[SbomCrossReference]
    truncated: bool
    cap: int


@strawberry.type
class SbomBulkResult:
    """Per-query matches plus a flag that the underlying row fan-out was capped.

    When ``truncated`` is true the component-row scan hit its cap, so some
    queries' match data (notably their ``repos`` list, or a found/not-found
    verdict) may be incomplete. The UI surfaces this rather than implying the
    exposure check was exhaustive.
    """
    matches: list[SbomBulkMatch]
    truncated: bool
    # True when the pasted list exceeded MAX_BULK_ITEMS and only ``accepted_count``
    # were checked — the rest appear in NO bucket, so the UI must say so rather
    # than imply the whole manifest was scanned.
    input_truncated: bool = False
    accepted_count: int = 0


def _parse_version_tuple(v: str) -> tuple[int, ...] | None:
    """Parse a version string into a comparable tuple of ints, or None when it
    has no numeric component. A single leading 'v' (Go module style, e.g.
    'v1.5.0') is stripped so it compares as '1.5.0'. Returning None (rather than
    coercing to (0,)) lets callers EXCLUDE unparseable versions from a numeric
    filter instead of silently treating them as version 0.

    The last element is a release indicator (1 = full release, 0 = pre-release
    or build metadata present) so that '1.0.0-beta' compares as strictly less
    than '1.0.0' rather than equal."""
    v = v.strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    result: list[int] = []
    has_prerelease = False
    for p in v.split("."):
        m = re.match(r"^(\d+)([-+].+)?$", p)
        if m:
            result.append(int(m.group(1)))
            if m.group(2):
                has_prerelease = True
                break
        elif re.match(r"^\d+$", p):
            result.append(int(p))
        else:
            has_prerelease = True
            break
    if not result:
        return None
    result.append(0 if has_prerelease else 1)
    return tuple(result)


def sbom_search(
    *,
    search: Optional[str] = None,
    ecosystems: Optional[list[str]] = None,
    source: Optional[str] = None,
    repos: Optional[list[str]] = None,
    version_op: Optional[str] = None,
    version_value: Optional[str] = None,
    version_value_end: Optional[str] = None,
    filter_logic: Optional[str] = None,
    vulnerable_only: Optional[bool] = None,
    license_categories: Optional[list[str]] = None,
    dependency: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    info_context: dict,
) -> SbomComponentsConnection:
    """Search SBOM components across all user assets."""
    per_page = clamp_per_page(per_page)
    page = max(1, page)
    search = (search or "").strip()[:200] or None
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return SbomComponentsConnection(items=[], total=0, page=page, per_page=per_page, total_pages=0)

    use_or = filter_logic == "or"

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        # Joins Asset so repo/org display info is available per row.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()
        base = (
            select(SbomComponent, Asset)
            .join(Sbom, SbomComponent.asset_id == Sbom.asset_id)
            .join(Asset, Asset.id == SbomComponent.asset_id)
            .where(Sbom.id.in_(allowed_sbom_ids))
        )

        if search:
            try:
                node = parse_search_query(search)
                predicate = compile_query(node, SbomComponent=SbomComponent, Asset=Asset)
            except SearchQueryError as e:
                raise_bad_input(str(e))
            base = base.where(predicate)

        # Build group conditions for AND/OR toggle
        group_conditions = []
        if ecosystems:
            group_conditions.append(SbomComponent.ecosystem.in_([e.lower() for e in ecosystems]))
        if source:
            # Repo vs container is the Asset.type (already joined), NOT source_tool
            # — container scans also stamp source_tool="syft", so filtering on it
            # inverted the result. source_tool stays for syft/cdxgen/both provenance.
            if source == "dependencies":
                group_conditions.append(Asset.type == "repo")
            elif source == "containers":
                group_conditions.append(Asset.type == "image")
        if repos:
            # `repos` are human-readable display_names (e.g. "acme/foo");
            # resolve to asset_ids and intersect with the SBOM scope.
            group_conditions.append(
                SbomComponent.asset_id.in_(
                    select(Asset.id).where(Asset.display_name.in_(repos))
                )
            )
        if license_categories:
            group_conditions.append(SbomComponent.license_category.in_(license_categories))
        if dependency == "direct":
            group_conditions.append(SbomComponent.is_direct.is_(True))
        elif dependency == "transitive":
            group_conditions.append(SbomComponent.is_direct.is_(False))
        elif dependency == "unknown":
            group_conditions.append(SbomComponent.is_direct.is_(None))

        if group_conditions:
            combiner = or_ if use_or else and_
            base = base.where(combiner(*group_conditions))

        if vulnerable_only:
            # Keep only components with at least one open finding mapped on the
            # same asset by package name. Correlated EXISTS so it composes with
            # the count + pagination (and the version full-scan) below.
            base = base.where(
                exists().where(
                    Finding.asset_id == SbomComponent.asset_id,
                    Finding.package_name == SbomComponent.name,
                    Finding.state == "open",
                    Finding.archived.is_(False),
                )
            )

        offset = (page - 1) * per_page
        truncated = False

        if version_op and version_value:
            # Semver comparison isn't reliable in SQL, so the version filter pulls
            # candidate rows and compares in Python — bounded by _MAX_VERSION_SCAN
            # to stay memory-safe. The unconditional count/page queries are skipped
            # here: they'd be pure wasted work, overwritten by the scan below.
            target = _parse_version_tuple(version_value)
            if target is None:
                raise_bad_input(f"Invalid version filter value: {version_value!r}")
            target_end = None
            if version_value_end:
                target_end = _parse_version_tuple(version_value_end)
                if target_end is None:
                    raise_bad_input(f"Invalid version filter value: {version_value_end!r}")

            def _version_match(comp):
                v = _parse_version_tuple(comp.version)
                if v is None:
                    # A component whose version has no numeric part (e.g. a git
                    # SHA, 'latest') can't satisfy a numeric comparison — exclude
                    # it rather than treat it as version 0.
                    return False
                if version_op == "eq":
                    return v == target
                if version_op == "gte":
                    return v >= target
                if version_op == "gt":
                    return v > target
                if version_op == "lte":
                    return v <= target
                if version_op == "lt":
                    return v < target
                if version_op == "range" and target_end:
                    return target <= v <= target_end
                return False

            # Fetch one past the cap so "exactly cap" doesn't false-positive as
            # truncated.
            all_rows = (
                await session.execute(
                    base.order_by(SbomComponent.name, SbomComponent.version)
                    .limit(_MAX_VERSION_SCAN + 1)
                )
            ).all()
            truncated = len(all_rows) > _MAX_VERSION_SCAN
            if truncated:
                # Only the first _MAX_VERSION_SCAN rows (name-ordered) were seen;
                # later components are excluded. total/page are therefore partial
                # — flagged to the client so the cap isn't invisible.
                all_rows = all_rows[:_MAX_VERSION_SCAN]
                logger.warning(
                    "sbom_search version filter hit the %d-row scan cap; results may "
                    "be incomplete — narrow the search/ecosystem/repo/scope filters.",
                    _MAX_VERSION_SCAN,
                )

            all_filtered = [(r, a) for r, a in all_rows if _version_match(r)]
            total = len(all_filtered)
            rows = all_filtered[offset:offset + per_page]
        else:
            count_q = select(func.count()).select_from(base.subquery())
            total = (await session.execute(count_q)).scalar() or 0
            rows = (
                await session.execute(
                    base.order_by(SbomComponent.name, SbomComponent.version)
                    .offset(offset)
                    .limit(per_page)
                )
            ).all()

        # Overlay open-finding severity counts per component VERSION. Findings
        # carry package_version (#1218), so attribute the exact (asset, name,
        # version) counts plus a name-level bucket for findings with no resolved
        # version (they apply to any version of the name). Without this a patched
        # version row would show another version's vulnerabilities. Components are
        # already asset-scoped, so this stays within the caller's scope.
        versioned_map: dict[tuple[str, str, str], dict[str, int]] = {}
        name_level_map: dict[tuple[str, str], dict[str, int]] = {}
        if rows:
            page_asset_ids = list({r.asset_id for r, _ in rows})
            page_names = list({r.name for r, _ in rows})
            vuln_q = (
                select(
                    Finding.asset_id,
                    Finding.package_name,
                    Finding.package_version,
                    Finding.severity,
                    func.count(),
                )
                .where(
                    Finding.asset_id.in_(page_asset_ids),
                    Finding.package_name.in_(page_names),
                    Finding.state == "open",
                    Finding.archived.is_(False),
                )
                .group_by(
                    Finding.asset_id,
                    Finding.package_name,
                    Finding.package_version,
                    Finding.severity,
                )
            )
            for aid, pkg, ver, sev, cnt in (await session.execute(vuln_q)).all():
                bucket = (
                    versioned_map.setdefault((aid, pkg, ver), _zero_vuln_counts())
                    if ver is not None
                    else name_level_map.setdefault((aid, pkg), _zero_vuln_counts())
                )
                tier = (sev or "").lower()
                if tier in bucket:
                    bucket[tier] += cnt
                bucket["total"] += cnt

        def _component_vulns(aid: str, name: str, version: str) -> ComponentVulnCounts:
            exact = versioned_map.get((aid, name, version))
            name_level = name_level_map.get((aid, name))
            if exact is None and name_level is None:
                return ComponentVulnCounts()
            merged = _zero_vuln_counts()
            for src in (exact, name_level):
                if src:
                    for key in merged:
                        merged[key] += src[key]
            return ComponentVulnCounts(**merged)

        items = [
            SbomComponentNode(
                name=r.name,
                version=r.version,
                ecosystem=r.ecosystem,
                purl=r.purl,
                repo=a.display_name,
                org=_safe_owner_from_ref(a.external_ref),
                source_tool=r.source_tool,
                scanned_at=r.scanned_at.isoformat() if r.scanned_at else "",
                is_container=a.type == "image",
                vulns=_component_vulns(r.asset_id, r.name, r.version),
                license=r.license_expression,
                license_category=r.license_category,
                is_direct=r.is_direct,
            )
            for r, a in rows
        ]

        total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0
        return SbomComponentsConnection(
            items=items, total=total, page=page, per_page=per_page,
            total_pages=total_pages, truncated=truncated,
        )

    return run_db(_query)


def sbom_filter_options(*, info_context: dict) -> SbomFilterOptions:
    """Return available filter values for SBOM search."""
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return SbomFilterOptions(
            ecosystems=[], repositories=[], sources=[], license_categories=[],
            dependency_scopes=[],
        )

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()
        asset_join = SbomComponent.asset_id == Sbom.asset_id

        eco_q = (
            select(SbomComponent.ecosystem)
            .join(Sbom, asset_join)
            .where(Sbom.id.in_(allowed_sbom_ids), SbomComponent.ecosystem != "")
            .distinct()
            .order_by(SbomComponent.ecosystem)
        )
        ecosystems = [r[0] for r in (await session.execute(eco_q)).all()]

        sources = ["dependencies", "containers"]
        repo_q = (
            select(Asset.display_name)
            .where(Asset.id.in_(asset_ids), Asset.type == "repo")
            .distinct()
            .order_by(Asset.display_name)
        )
        repositories = [r[0] for r in (await session.execute(repo_q)).all() if r[0]]

        lic_q = (
            select(SbomComponent.license_category)
            .join(Sbom, asset_join)
            .where(Sbom.id.in_(allowed_sbom_ids), SbomComponent.license_category.is_not(None))
            .distinct()
        )
        # Worst-first so the facet leads with the categories that need review.
        license_categories = sorted(
            (r[0] for r in (await session.execute(lic_q)).all()),
            key=category_rank, reverse=True,
        )

        dep_q = (
            select(SbomComponent.is_direct)
            .join(Sbom, asset_join)
            .where(Sbom.id.in_(allowed_sbom_ids))
            .distinct()
        )
        present = {r[0] for r in (await session.execute(dep_q)).all()}
        _scope_name = {True: "direct", False: "transitive", None: "unknown"}
        dependency_scopes = [_scope_name[v] for v in (True, False, None) if v in present]

        return SbomFilterOptions(
            ecosystems=ecosystems, repositories=repositories, sources=sources,
            license_categories=license_categories, dependency_scopes=dependency_scopes,
        )

    return run_db(_query)


def sbom_cross_references(
    *, purl: str, info_context: dict
) -> SbomCrossRefResult:
    """Find all repos/images that contain a specific package (by PURL)."""
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return SbomCrossRefResult(items=[], truncated=False, cap=_MAX_CROSS_REFS)

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()
        q = (
            select(SbomComponent, Asset)
            .join(Sbom, SbomComponent.asset_id == Sbom.asset_id)
            .join(Asset, Asset.id == SbomComponent.asset_id)
            .where(
                Sbom.id.in_(allowed_sbom_ids),
                SbomComponent.purl == purl,
            )
            .order_by(SbomComponent.asset_id)
            # Fetch one past the cap so we can tell "exactly cap" from "more
            # than cap" and report truncation honestly to the UI.
            .limit(_MAX_CROSS_REFS + 1)
        )
        rows = (await session.execute(q)).all()
        truncated = len(rows) > _MAX_CROSS_REFS
        items = [
            SbomCrossReference(
                repo=a.display_name,
                org=_safe_owner_from_ref(a.external_ref),
                version=r.version,
                source_tool=r.source_tool,
                scanned_at=r.scanned_at.isoformat() if r.scanned_at else "",
                is_container=a.type == "image",
                license=r.license_expression,
                license_category=r.license_category,
            )
            for r, a in rows[:_MAX_CROSS_REFS]
        ]
        return SbomCrossRefResult(items=items, truncated=truncated, cap=_MAX_CROSS_REFS)

    return run_db(_query)


def sbom_component_vulns(
    *, repo: str, info_context: dict
) -> list[RepoComponentVulns]:
    """Per-package open-finding severity counts for one repository's SBOM.

    Scope is enforced by resolving the repo's asset within the caller's grant
    set; an out-of-scope or unknown repo yields an empty list so existence is
    never revealed to a viewer who cannot see the asset. Counts are grouped by
    the exact ``package_name``, matching the explorer's (asset_id, name) join,
    so the client can key directly off each parsed SBOM component's name.
    """
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return []

    async def _query(session):
        asset_id = (
            await session.execute(
                select(Asset.id)
                .where(Asset.display_name == repo)
                .where(Asset.type == "repo")
                .where(Asset.id.in_(asset_ids))
                # display_name isn't unique (a repo can be mirrored across a
                # GitHub and a GitLab source), so order for a stable pick.
                .order_by(Asset.id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if asset_id is None:
            return []

        rows = (
            await session.execute(
                select(
                    Finding.package_name,
                    Finding.package_version,
                    Finding.severity,
                    func.count(),
                )
                .where(
                    Finding.asset_id == asset_id,
                    Finding.state == "open",
                    Finding.archived.is_(False),
                    Finding.package_name.is_not(None),
                )
                .group_by(Finding.package_name, Finding.package_version, Finding.severity)
            )
        ).all()

        # Key by (name, version); version None is the name-level bucket (findings
        # whose source didn't resolve a version) and the client applies it to
        # every version of that name.
        agg: dict[tuple[str, Optional[str]], dict[str, int]] = {}
        for pkg, ver, sev, cnt in rows:
            bucket = agg.setdefault(
                (pkg, ver), {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
            )
            tier = (sev or "").lower()
            if tier in bucket:
                bucket[tier] += cnt
            bucket["total"] += cnt

        return [
            RepoComponentVulns(
                package_name=pkg, package_version=ver, vulns=ComponentVulnCounts(**counts)
            )
            for (pkg, ver), counts in agg.items()
        ]

    return run_db(_query)


def sbom_risky_components(
    *,
    search: Optional[str] = None,
    ecosystems: Optional[list[str]] = None,
    page: int = 1,
    per_page: int = 25,
    info_context: dict,
) -> RiskyComponentsConnection:
    """Estate-wide vulnerable packages ranked by severity weight + blast radius.

    Aggregates open, non-archived findings by ``(package_name, ecosystem)``
    across every asset in the caller's scope, returning severity-bucketed counts
    and the number of distinct assets affected. Ranked by severity tier — any
    package with a critical outranks one without, then by high/medium/low counts
    — with blast radius (then total) breaking ties. Optional name search +
    ecosystem filter.

    Findings carry no ecosystem, so it's resolved from the SBOM (a distinct
    (asset, name, ecosystem) mapping): a name that legitimately spans two
    ecosystems in scope is split into one row each, with accurate per-ecosystem
    counts and blast radius, and the ecosystem filter matches the resolved
    ecosystem (not bare name membership). A name that resolves to a single
    ecosystem in scope stays one row even where a finding sits on an asset whose
    SBOM lacks the component (a single-ecosystem fallback prevents fragmenting it
    into a spurious blank row). Only a name with NO ecosystem anywhere in scope
    lands in a blank ("unknown") ecosystem row.
    """
    per_page = clamp_per_page(per_page)
    page = max(1, page)
    search = (search or "").strip()[:200] or None
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return RiskyComponentsConnection(items=[], total=0, page=page, per_page=per_page, total_pages=0)

    def _sev(tier: str):
        # FILTER count for one severity tier; case/null-insensitive to match the
        # bucketing used by the component vuln overlay.
        return func.count().filter(func.lower(func.coalesce(Finding.severity, "")) == tier)

    async def _query(session):
        conds = [
            Finding.asset_id.in_(asset_ids),
            Finding.state == "open",
            Finding.archived.is_(False),
            Finding.package_name.is_not(None),
        ]
        if search:
            conds.append(Finding.package_name.ilike(f"%{_escape_like(search)}%"))
        # Findings carry no ecosystem, so resolve it from the SBOM: a distinct
        # (asset_id, name, ecosystem) mapping. Versions of one package collapse to
        # a single row per ecosystem; a name that legitimately spans two
        # ecosystems in one asset contributes to both. A finding whose package is
        # in no current SBOM LEFT-joins to nothing and falls to a blank-ecosystem
        # ("unknown") group — never dropped.
        eco_sub = (
            select(
                SbomComponent.asset_id.label("asset_id"),
                SbomComponent.name.label("name"),
                SbomComponent.ecosystem.label("ecosystem"),
            )
            .where(SbomComponent.asset_id.in_(asset_ids), SbomComponent.ecosystem != "")
            .distinct()
            .subquery()
        )
        # Names that resolve to exactly ONE ecosystem across scope. Used as a
        # fallback so a single-ecosystem package whose finding sits on an asset
        # missing the component (SBOM not ingested there, or a blank stored
        # ecosystem) still resolves to that one ecosystem instead of fragmenting
        # into a separate blank ("unknown") row. Only names spanning 2+
        # ecosystems fall through to the per-asset split.
        name_single_sub = (
            select(
                SbomComponent.name.label("name"),
                func.min(SbomComponent.ecosystem).label("sole_eco"),
            )
            .where(SbomComponent.asset_id.in_(asset_ids), SbomComponent.ecosystem != "")
            .group_by(SbomComponent.name)
            .having(func.count(distinct(SbomComponent.ecosystem)) == 1)
            .subquery()
        )
        eco_col = func.coalesce(eco_sub.c.ecosystem, name_single_sub.c.sole_eco, "")
        if ecosystems:
            # Ecosystem-accurate filter: match the RESOLVED ecosystem, not bare
            # name membership (which let a same-named other-ecosystem package in).
            conds.append(eco_col.in_([e.lower() for e in ecosystems]))

        crit, high, med, low = _sev("critical"), _sev("high"), _sev("medium"), _sev("low")
        agg = (
            select(
                Finding.package_name.label("pkg"),
                eco_col.label("eco"),
                func.count().label("total"),
                func.count(distinct(Finding.asset_id)).label("repos"),
                crit.label("c"),
                high.label("h"),
                med.label("m"),
                low.label("l"),
            )
            .select_from(Finding)
            .outerjoin(
                eco_sub,
                and_(
                    Finding.asset_id == eco_sub.c.asset_id,
                    Finding.package_name == eco_sub.c.name,
                ),
            )
            .outerjoin(name_single_sub, Finding.package_name == name_single_sub.c.name)
            .where(*conds)
            .group_by(Finding.package_name, eco_col)
        )

        total = (await session.execute(select(func.count()).select_from(agg.subquery()))).scalar() or 0

        offset = (page - 1) * per_page
        rows = (
            await session.execute(
                agg.order_by(
                    desc("c"), desc("h"), desc("m"), desc("l"),
                    desc("repos"), desc("total"), Finding.package_name, eco_col,
                )
                .offset(offset)
                .limit(per_page)
            )
        ).all()

        # Worst-case license per package name (a property of the component, not
        # the ecosystem split): the most-restrictive category on any in-scope
        # component for the name, so a high-blast-radius copyleft package stays
        # visible without leaving the risk view.
        lic_map: dict[str, tuple[Optional[str], Optional[str]]] = {}
        page_names = [r.pkg for r in rows]
        if page_names:
            comp_rows = (
                await session.execute(
                    select(
                        SbomComponent.name,
                        SbomComponent.license_category,
                        SbomComponent.license_expression,
                    )
                    .where(
                        SbomComponent.asset_id.in_(asset_ids),
                        SbomComponent.name.in_(page_names),
                    )
                    .distinct()
                )
            ).all()
            for name, lic_cat, lic_expr in comp_rows:
                if lic_cat:
                    prev = lic_map.get(name)
                    if prev is None or category_rank(lic_cat) > category_rank(prev[0]):
                        lic_map[name] = (lic_cat, lic_expr)

        items = [
            RiskyComponent(
                package_name=r.pkg,
                ecosystem=r.eco,
                repo_count=r.repos,
                vulns=ComponentVulnCounts(critical=r.c, high=r.h, medium=r.m, low=r.l, total=r.total),
                license_category=lic_map.get(r.pkg, (None, None))[0],
                license=lic_map.get(r.pkg, (None, None))[1],
            )
            for r in rows
        ]
        total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0
        return RiskyComponentsConnection(
            items=items, total=total, page=page, per_page=per_page, total_pages=total_pages
        )

    return run_db(_query)


def sbom_package_repos(
    *, package_name: str, ecosystem: Optional[str] = None, info_context: dict
) -> list[PackageRepo]:
    """The repositories affected by a package's open vulnerabilities — the
    "where used" drill-down behind a Risky Packages blast-radius count.

    Returns one entry per in-scope asset with an open, non-archived finding on
    ``package_name``, each with its severity breakdown, worst-first. Scope is
    enforced at the SQL layer; empty/absent scope yields an empty list.

    When ``ecosystem`` is given (Risky Packages rows are per (name, ecosystem)),
    the list is restricted to assets whose finding on the name resolves to that
    ecosystem — mirroring ``sbom_risky_components`` — so the drill-down list and
    per-repo counts reconcile with the row's blast-radius count. ``""`` selects
    the unknown-ecosystem assets. ``None`` keeps the legacy name-wide behaviour.
    """
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids or not package_name:
        return []

    async def _query(session):
        finding_q = select(Finding.asset_id, Finding.severity, func.count()).where(
            Finding.asset_id.in_(asset_ids),
            Finding.package_name == package_name,
            Finding.state == "open",
            Finding.archived.is_(False),
        )
        if ecosystem is not None:
            eco_sub = (
                select(SbomComponent.asset_id, SbomComponent.ecosystem)
                .where(
                    SbomComponent.asset_id.in_(asset_ids),
                    SbomComponent.name == package_name,
                    SbomComponent.ecosystem != "",
                )
                .distinct()
                .subquery()
            )
            # Single-ecosystem fallback for this name (matches the risky resolver).
            distinct_ecos = (
                await session.execute(
                    select(SbomComponent.ecosystem)
                    .where(
                        SbomComponent.asset_id.in_(asset_ids),
                        SbomComponent.name == package_name,
                        SbomComponent.ecosystem != "",
                    )
                    .distinct()
                )
            ).scalars().all()
            sole_eco = distinct_ecos[0] if len(distinct_ecos) == 1 else None
            eco_expr = func.coalesce(eco_sub.c.ecosystem, sole_eco, "")
            finding_q = (
                finding_q.select_from(Finding)
                .outerjoin(eco_sub, Finding.asset_id == eco_sub.c.asset_id)
                .where(eco_expr == ecosystem.lower())
            )
        rows = (
            await session.execute(finding_q.group_by(Finding.asset_id, Finding.severity))
        ).all()

        agg: dict[str, dict[str, int]] = {}
        for aid, sev, cnt in rows:
            bucket = agg.setdefault(
                aid, {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
            )
            tier = (sev or "").lower()
            if tier in bucket:
                bucket[tier] += cnt
            bucket["total"] += cnt

        if not agg:
            return []

        assets = (
            await session.execute(
                select(Asset.id, Asset.display_name, Asset.external_ref, Asset.type).where(
                    Asset.id.in_(list(agg.keys()))
                )
            )
        ).all()
        amap = {a.id: a for a in assets}

        result = [
            PackageRepo(
                repo=amap[aid].display_name or "",
                org=_safe_owner_from_ref(amap[aid].external_ref),
                is_container=amap[aid].type == "image",
                vulns=ComponentVulnCounts(**counts),
            )
            for aid, counts in agg.items()
            if aid in amap
        ]
        result.sort(
            key=lambda r: (r.vulns.critical, r.vulns.high, r.vulns.medium, r.vulns.low, r.vulns.total),
            reverse=True,
        )
        return result

    return run_db(_query)


def sbom_bulk_lookup(
    *, queries: list[str], info_context: dict
) -> SbomBulkResult:
    """Check which packages from a list exist in the estate."""
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids or not queries:
        return SbomBulkResult(matches=[], truncated=False)

    # Cap the pasted list, but report when we drop the overflow so the UI doesn't
    # imply the whole manifest was checked.
    nonempty = [q.strip() for q in queries if q.strip()]
    input_truncated = len(nonempty) > MAX_BULK_ITEMS
    clean = nonempty[:MAX_BULK_ITEMS]
    if not clean:
        return SbomBulkResult(matches=[], truncated=False)

    # Parse once: strip any pinned @version off each query. A pinned version
    # never narrows the DB fetch (it only flags occurrences in Python), so the
    # match path keys off the version-stripped form.
    parsed = [(q, *_parse_bulk_query(q)) for q in clean]

    # Versionless purl candidates (rare exact match) plus the name candidates
    # the name index can reach — for a purl that's the decoded package name, for
    # a plain query it's the version-stripped name itself.
    purl_candidates = {mq for _, mq, _, _ in parsed if mq.startswith("pkg:")}
    name_candidates: set[str] = set()
    for q, mq, _eco, _ver in parsed:
        if mq.startswith("pkg:"):
            nq = _purl_name(mq)
            if nq:
                name_candidates.add(nq)
        elif mq:
            name_candidates.add(mq.lower())

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        # One batched query for the whole list instead of a per-item query —
        # the old loop issued up to MAX_BULK_ITEMS sequential statements, each a
        # leading-wildcard seq scan of sbom_components.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()

        match_conditions = []
        if purl_candidates:
            match_conditions.append(SbomComponent.purl.in_(list(purl_candidates)))
        if name_candidates:
            # Exact (case-insensitive) names collapse into one sargable IN rather
            # than one ILIKE per name; only the scoped "group/name" suffix form —
            # so a bare query still matches packages like "@scope/name" — needs a
            # per-name leading-wildcard LIKE (inherently non-sargable).
            match_conditions.append(
                func.lower(SbomComponent.name).in_(list(name_candidates))
            )
            for nq in name_candidates:
                match_conditions.append(SbomComponent.name.ilike(f"%/{_escape_like(nq)}"))

        rows = []
        truncated = False
        if match_conditions:
            rows = (
                await session.execute(
                    select(SbomComponent, Asset.display_name)
                    .join(Sbom, SbomComponent.asset_id == Sbom.asset_id)
                    .join(Asset, Asset.id == SbomComponent.asset_id)
                    .where(Sbom.id.in_(allowed_sbom_ids), or_(*match_conditions))
                    .order_by(SbomComponent.name)
                    # One past the cap to distinguish "exactly cap" from "more".
                    .limit(_MAX_BULK_ROWS + 1)
                )
            ).all()
            truncated = len(rows) > _MAX_BULK_ROWS
            if truncated:
                rows = rows[:_MAX_BULK_ROWS]
                logger.warning(
                    "sbom_bulk_lookup hit the %d-row cap; matches for some queries "
                    "may be truncated.", _MAX_BULK_ROWS,
                )

        # Index the matched rows so each input query is attributed in O(1):
        # by exact PURL, by lower-cased name, and by the bare name after the
        # last slash (the suffix form).
        by_purl: dict[str, list] = {}
        by_name: dict[str, list] = {}
        by_bare: dict[str, list] = {}
        for comp, display_name in rows:
            by_purl.setdefault(comp.purl, []).append((comp, display_name))
            nl = comp.name.lower()
            by_name.setdefault(nl, []).append((comp, display_name))
            if "/" in nl:
                by_bare.setdefault(nl.rsplit("/", 1)[-1], []).append((comp, display_name))

        def _match_name(ql: str) -> list:
            if "/" in ql:
                # Multi-segment query: exact name, or any name ending in "/<q>".
                suffix = "/" + ql
                return [
                    pair
                    for nl, pairs in by_name.items()
                    if nl == ql or nl.endswith(suffix)
                    for pair in pairs
                ]
            return by_name.get(ql, []) + by_bare.get(ql, [])

        results: list[SbomBulkMatch] = []
        for q, mq, _eco, flagged_version in parsed:
            if mq.startswith("pkg:"):
                # Exact versionless purl is rare (stored purls carry the
                # version), so reach the rows by the decoded name too.
                matched = list(by_purl.get(mq, []))
                nq = _purl_name(mq)
                if nq:
                    matched += _match_name(nq)
            else:
                matched = _match_name(mq.lower())

            # Collapse rows that resolved through more than one index.
            uniq = {id(comp): (comp, dn) for comp, dn in matched}
            matched = list(uniq.values())

            if matched:
                seen: set[tuple[str, str]] = set()
                occs: list[SbomBulkOccurrence] = []
                for comp, dn in matched:
                    if not dn:
                        continue
                    key = (dn, comp.version or "")
                    if key in seen:
                        continue
                    seen.add(key)
                    latent = (
                        flagged_version is not None
                        and comp.version != flagged_version
                        and declared_range_admits(
                            comp.ecosystem, comp.declared_range, flagged_version
                        )
                    )
                    occs.append(SbomBulkOccurrence(
                        repo=dn, version=comp.version or "",
                        flagged=flagged_version is not None and comp.version == flagged_version,
                        latent=latent,
                    ))
                # Flagged-first, then latent, so the highest-signal occurrences
                # always survive the per-query cap.
                occs.sort(key=lambda o: (not o.flagged, not o.latent, o.repo, o.version))
                any_flagged = any(o.flagged for o in occs)
                any_latent = any(o.latent for o in occs)
                occurrence_total = len(occs)
                occs = occs[:_MAX_BULK_OCCURRENCES]

                if flagged_version is None:
                    exposure = "present"
                elif any_flagged:
                    exposure = "flagged_in_use"
                elif any_latent:
                    exposure = "latent"
                else:
                    exposure = "other_versions"

                first = matched[0][0]
                worst = max(
                    (c for c, _ in matched),
                    key=lambda c: category_rank(c.license_category),
                )
                results.append(SbomBulkMatch(
                    query=q, found=True, name=first.name, ecosystem=first.ecosystem,
                    purl=first.purl, queried_version=flagged_version,
                    exposure=exposure, occurrences=occs,
                    occurrence_total=occurrence_total,
                    occurrences_truncated=occurrence_total > _MAX_BULK_OCCURRENCES,
                    license=worst.license_expression,
                    license_category=worst.license_category,
                ))
            else:
                results.append(SbomBulkMatch(
                    query=q, found=False, name="", ecosystem="", purl="",
                    queried_version=flagged_version, exposure="not_found",
                    occurrences=[],
                ))

        return SbomBulkResult(
            matches=results, truncated=truncated,
            input_truncated=input_truncated, accepted_count=len(clean),
        )

    return run_db(_query)


# ── SBOM run history + diff ──────────────────────────────────────────────────


@strawberry.type
class SbomHistoryEntry:
    run_id: str
    created_at: Optional[str]
    key: str


@strawberry.type
class SbomDiffComponent:
    name: str
    version: str
    purl: str
    type: str
    # Open findings on the to-side asset for this package (current state).
    current_findings: ComponentVulnCounts = strawberry.field(default_factory=ComponentVulnCounts)
    # OSV advisories affecting this exact version — on an added row this is the
    # vulnerability it introduced; on a removed row, the one dropping it cleared.
    known_vulns: ComponentVulnCounts = strawberry.field(default_factory=ComponentVulnCounts)


@strawberry.type
class SbomVersionChange:
    name: str
    purl: str
    from_version: Optional[str]
    to_version: Optional[str]
    # Component ecosystem/type (e.g. npm, pypi) — mirrors added/removed rows.
    type: str = ""
    # OSV advisory set-delta between the two versions (re-match vs today's mirror).
    resolved: ComponentVulnCounts = strawberry.field(default_factory=ComponentVulnCounts)
    introduced: ComponentVulnCounts = strawberry.field(default_factory=ComponentVulnCounts)
    still_vulnerable: ComponentVulnCounts = strawberry.field(default_factory=ComponentVulnCounts)
    # Open findings on the to-side asset for this package (current state).
    current_findings: ComponentVulnCounts = strawberry.field(default_factory=ComponentVulnCounts)
    # License before/after the bump + their risk categories — a change is a
    # compliance event (e.g. MIT -> GPL-3.0-only).
    from_license: Optional[str] = None
    to_license: Optional[str] = None
    from_license_category: Optional[str] = None
    to_license_category: Optional[str] = None


@strawberry.type
class SbomDiffResult:
    added: list[SbomDiffComponent]
    removed: list[SbomDiffComponent]
    version_changed: list[SbomVersionChange]
    unchanged_count: int
    # False when the OSV mirror is empty or the diff exceeded the re-match cap —
    # the client must render the resolved/introduced/dropped deltas as
    # "unavailable" rather than a misleading zero.
    remediation_signal_available: bool = True
    # True totals before the node lists are capped (a huge container diff can run
    # to thousands of changes); ``truncated`` is set when any list was clipped so
    # the client shows the real count and a "first N" note rather than the page.
    added_count: int = 0
    removed_count: int = 0
    version_changed_count: int = 0
    truncated: bool = False


@strawberry.type
class SbomDiffError:
    message: str
    code: str


SbomDiffOrError = Annotated[
    Union[SbomDiffResult, SbomDiffError],
    strawberry.union("SbomDiffOrError"),
]


_MAX_HISTORY_LIMIT = 100
_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_\-][A-Za-z0-9._\-]*$")
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-][A-Za-z0-9._\-]*$")
_IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[A-Fa-f0-9]{64}$")


def _safe_segment(s: str) -> bool:
    """Return True iff ``s`` is a safe path segment.

    Rejects empty strings, dot/dotdot segments, leading dots, and any
    character outside the allowlist. The leading-dot rule blocks the
    classic ``.git`` / ``..foo`` traversal vectors before the value can
    flow into MinIO prefix concatenation.
    """
    if s in (".", ".."):
        return False
    if ".." in s:
        return False
    return bool(_SEGMENT_PATTERN.match(s))


def _validate_repo_id(repo_id: str) -> tuple[str, str] | None:
    """Return (owner, name) if repo_id is a safe owner/name pair, else None.

    Input flows into a MinIO prefix concatenation, so the allowlist must
    be strict — any traversal or unexpected character returns None and
    the caller short-circuits to a uniform "not found" response.
    """
    parts = repo_id.split("/")
    if len(parts) != 2:
        return None
    owner, name = parts
    if not _safe_segment(owner) or not _safe_segment(name):
        return None
    return owner, name


def _safe_run_id(run_id: str) -> bool:
    return _safe_segment(run_id) and bool(_RUN_ID_PATTERN.match(run_id))


def _resolve_repo_asset_id(repo_id: str, asset_ids: list[str]) -> str | None:
    """Resolve a repo display_name to its asset id within the caller's scope,
    or None if out of scope / unknown — the scope gate for the repo diff path."""
    if not asset_ids:
        return None

    async def _query(session):
        result = await session.execute(
            select(Asset.id)
            .where(Asset.display_name == repo_id)
            .where(Asset.type == "repo")
            .where(Asset.id.in_(asset_ids))
            # display_name isn't unique across sources — order for a stable pick
            # so diff and history resolve the same asset.
            .order_by(Asset.id)
            .limit(1)
        )
        return result.scalar_one_or_none()

    return run_db(_query)


def _asset_owns_runs(asset_id: str, run_ids: list[str]) -> bool:
    """True only if every run id is a recorded ``SbomRun`` of this exact asset.

    ``display_name`` is not unique, but the dependency-SBOM MinIO key is built
    from ``owner/run_id/name`` with no asset qualifier — so two assets that
    share an owner/name (e.g. the same repo mirrored across a GitHub and a
    GitLab source) share a key prefix. Resolving the asset by display_name alone
    is therefore not enough: a caller scoped to one could pass the other's
    run id and read its snapshot. Binding each run id back to *this* asset's
    runs closes that cross-scope read."""
    wanted = {r for r in run_ids if r}
    if not wanted:
        return False

    async def _query(session):
        found = (
            await session.execute(
                select(SbomRun.run_id).where(
                    SbomRun.asset_id == asset_id,
                    SbomRun.run_id.in_(list(wanted)),
                )
            )
        ).scalars().all()
        return wanted.issubset(set(found))

    return run_db(_query)


def _run_id_to_iso(run_id: str) -> str | None:
    if run_id.startswith("auto-"):
        try:
            ms = int(run_id[5:])
            return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    return None


def sbom_history(
    *,
    repo: str,
    limit: int = 10,
    info_context: dict,
) -> list[SbomHistoryEntry]:
    """List historical SBOM run entries for a repository.

    Returns at most ``limit`` entries (clamped to 1..100), newest first.
    Out-of-scope or non-existent repos return an empty list — never reveal
    existence to a viewer who cannot see the asset.

    Backed by the indexed ``sbom_runs`` table; scope is resolved and the
    history paged in a single SQL round-trip so this stays bounded at scale.
    """
    asset_ids = info_context.get("asset_ids", [])
    limit = max(1, min(_MAX_HISTORY_LIMIT, limit))

    parsed = _validate_repo_id(repo)
    if parsed is None or not asset_ids:
        return []
    owner, name = parsed

    async def _query(session):
        asset_id = (
            await session.execute(
                select(Asset.id)
                .where(Asset.display_name == repo)
                .where(Asset.type == "repo")
                .where(Asset.id.in_(asset_ids))
                # display_name isn't unique (a repo can be mirrored across a
                # GitHub and a GitLab source), so order for a stable pick.
                .order_by(Asset.id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if asset_id is None:
            return []

        rows = (
            await session.execute(
                select(SbomRun.run_id, SbomRun.scanned_at)
                .where(SbomRun.asset_id == asset_id)
                .order_by(SbomRun.scanned_at.desc(), SbomRun.id.desc())
                .limit(limit)
            )
        ).all()

        return [
            SbomHistoryEntry(
                run_id=run_id,
                created_at=scanned_at.isoformat() if scanned_at else _run_id_to_iso(run_id),
                key=f"dependencies_scanning/{owner}/{run_id}/{name}/sbom.cdx.json",
            )
            for run_id, scanned_at in rows
        ]

    return run_db(_query)


def _component_to_diff(
    c: dict[str, Any], overlay: DiffOverlay, *, with_findings: bool
) -> SbomDiffComponent:
    """Build a diff component with its vuln overlay. ``with_findings`` is True for
    added rows (the package exists in the to-side asset, so current findings are
    meaningful) and False for removed rows (the package is gone — only the
    advisories its removal cleared, via ``known_vulns``, are meaningful)."""
    name = str(c.get("name") or "")
    version = str(c.get("version") or "")
    purl = str(c.get("purl") or "")
    findings = overlay.findings_for(name) if with_findings else None
    return SbomDiffComponent(
        name=name,
        version=version,
        purl=purl,
        type=str(c.get("type") or ""),
        current_findings=ComponentVulnCounts(**findings) if findings else ComponentVulnCounts(),
        known_vulns=ComponentVulnCounts(**overlay.known_vulns(name, version, purl)),
    )


def _fetch_container_sbom_by_digest(
    image_digest: str, asset_ids: list[str],
) -> tuple[dict[str, Any] | None, str | None]:
    """Return (sbom, asset_id) for an in-scope container image digest, or
    (None, None) when no in-scope row matches. Scope is enforced at the SQL
    layer so a digest shared across tenants resolves to the caller's own row
    rather than another tenant's (which would diff as a spurious not-found).
    Empty/absent scope returns (None, None) — fail-closed."""
    if not asset_ids:
        return None, None

    async def _query(session):
        result = await session.execute(
            select(Sbom)
            .where(Sbom.commit_sha == image_digest)
            .where(Sbom.asset_id.in_(asset_ids))
            .limit(1)
        )
        return result.scalars().first()

    row = run_db(_query)
    if row is None:
        return None, None
    sbom = download_from_minio(row.s3_key)
    return sbom, row.asset_id


def sbom_diff(
    *,
    repo_id: Optional[str] = None,
    from_run_id: Optional[str] = None,
    to_run_id: Optional[str] = None,
    image_digest_from: Optional[str] = None,
    image_digest_to: Optional[str] = None,
    info_context: dict,
) -> SbomDiffOrError:
    """Diff two SBOMs by repo+run or by container image digests.

    Either provide ``(repo_id, from_run_id, to_run_id)`` or
    ``(image_digest_from, image_digest_to)``. All not-found / out-of-scope
    paths return a uniform NOT_FOUND error so callers cannot distinguish
    "repo doesn't exist" from "you cannot see this repo".
    """
    asset_ids = info_context.get("asset_ids", [])
    not_found = SbomDiffError(message="One or both SBOMs not found.", code="NOT_FOUND")

    if repo_id is not None:
        if not from_run_id or not to_run_id:
            return SbomDiffError(
                message="from_run_id and to_run_id are required when repo_id is provided.",
                code="BAD_REQUEST",
            )
        parsed = _validate_repo_id(repo_id)
        if parsed is None or not _safe_run_id(from_run_id) or not _safe_run_id(to_run_id):
            return not_found
        to_asset_id = _resolve_repo_asset_id(repo_id, asset_ids)
        if to_asset_id is None:
            return not_found
        # Bind both run ids to this asset's own runs — the owner/name MinIO
        # prefix is shared across display_name-colliding assets, so scope by
        # asset alone would let a caller read a colliding asset's snapshot.
        if not _asset_owns_runs(to_asset_id, [from_run_id, to_run_id]):
            return not_found
        owner, name = parsed
        from_sbom = download_json(f"dependencies_scanning/{owner}/{from_run_id}/{name}/sbom.cdx.json")
        to_sbom = download_json(f"dependencies_scanning/{owner}/{to_run_id}/{name}/sbom.cdx.json")
    elif image_digest_from and image_digest_to:
        if not _IMAGE_DIGEST_PATTERN.match(image_digest_from) or not _IMAGE_DIGEST_PATTERN.match(image_digest_to):
            return not_found
        from_sbom, from_asset = _fetch_container_sbom_by_digest(image_digest_from, asset_ids)
        to_sbom, to_asset = _fetch_container_sbom_by_digest(image_digest_to, asset_ids)
        # SQL already scopes the fetch; this stays as a defensive backstop.
        scope = set(asset_ids)
        if (from_asset and from_asset not in scope) or (to_asset and to_asset not in scope):
            return not_found
        # Current-findings overlay anchors on the newer (to-side) image asset.
        to_asset_id = to_asset
    else:
        return SbomDiffError(
            message="Provide (repo_id + from_run_id + to_run_id) or (image_digest_from + image_digest_to).",
            code="BAD_REQUEST",
        )

    # A missing blob is None; a corrupt blob is None (download_json swallows the
    # parse error); a valid-JSON-but-not-CycloneDX blob is a non-dict. Treat all
    # three as not-found rather than diffing a degenerate side.
    if not isinstance(from_sbom, dict) or not isinstance(to_sbom, dict):
        return not_found

    diff = diff_sboms(from_sbom, to_sbom)

    async def _overlay_query(session):
        return await compute_diff_overlay(session, diff, to_asset_id)

    overlay = run_db(_overlay_query)

    # A container diff can run to thousands of node changes; cap each list so the
    # response (and the client render) stay bounded, while reporting the true
    # totals so the UI shows the real count, not the capped page.
    added_count = len(diff.added)
    removed_count = len(diff.removed)
    version_changed_count = len(diff.version_changed)
    truncated = (
        added_count > _MAX_DIFF_NODES
        or removed_count > _MAX_DIFF_NODES
        or version_changed_count > _MAX_DIFF_NODES
    )

    version_changed: list[SbomVersionChange] = []
    for v in diff.version_changed[:_MAX_DIFF_NODES]:
        name = v.get("name")
        purl = v.get("purl")
        resolved, introduced, still = overlay.version_delta(
            name, v.get("from_version"), v.get("to_version"), purl
        )
        from_lic = classify_licenses(v.get("from_licenses") or [])
        to_lic = classify_licenses(v.get("to_licenses") or [])
        version_changed.append(SbomVersionChange(
            name=str(name or ""),
            purl=str(purl or ""),
            type=str(v.get("type") or ""),
            from_version=v.get("from_version"),
            to_version=v.get("to_version"),
            resolved=ComponentVulnCounts(**resolved),
            introduced=ComponentVulnCounts(**introduced),
            still_vulnerable=ComponentVulnCounts(**still),
            current_findings=ComponentVulnCounts(**overlay.findings_for(name)),
            from_license=from_lic.expression,
            to_license=to_lic.expression,
            from_license_category=from_lic.category,
            to_license_category=to_lic.category,
        ))

    return SbomDiffResult(
        added=[_component_to_diff(c, overlay, with_findings=True) for c in diff.added[:_MAX_DIFF_NODES]],
        removed=[_component_to_diff(c, overlay, with_findings=False) for c in diff.removed[:_MAX_DIFF_NODES]],
        version_changed=version_changed,
        unchanged_count=diff.unchanged_count,
        remediation_signal_available=overlay.available,
        added_count=added_count,
        removed_count=removed_count,
        version_changed_count=version_changed_count,
        truncated=truncated,
    )


def sbom_ecosystem_analytics(info_context: dict[str, Any]) -> list[SbomEcosystemAnalytics]:
    """Aggregate SBOM components and findings at the ecosystem level.

    Returns risk coverage KPIs over the full scope (A3) - showing for each ecosystem:
    - Count of findings by severity
    - Count of components
    - Number of assets with components (coverage)
    - Number of assets with findings
    - Coverage percentage (assets with components / total assets)
    """
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return []

    total_assets = len(asset_ids)

    # SEVERITY_WEIGHTS from posture (copied here)
    SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}

    # Ecosystem resolution: a per-asset (name → single ecosystem) map plus a
    # scope-wide single-ecosystem fallback so a finding on an asset missing the
    # component still resolves. The per-asset map yields exactly one row per
    # (asset, name) — collapsing to min() when the same name appears in more than
    # one ecosystem on an asset (e.g. a JS and a Python "foo") so a single finding
    # is attributed to one ecosystem instead of fanning out and being counted
    # once per ecosystem.
    eco_sub = (
        select(
            SbomComponent.asset_id.label("asset_id"),
            SbomComponent.name.label("name"),
            func.min(SbomComponent.ecosystem).label("ecosystem"),
        )
        .where(SbomComponent.asset_id.in_(asset_ids), SbomComponent.ecosystem != "")
        .group_by(SbomComponent.asset_id, SbomComponent.name)
        .subquery()
    )
    name_single_sub = (
        select(
            SbomComponent.name.label("name"),
            func.min(SbomComponent.ecosystem).label("sole_eco"),
        )
        .where(SbomComponent.asset_id.in_(asset_ids), SbomComponent.ecosystem != "")
        .group_by(SbomComponent.name)
        .having(func.count(distinct(SbomComponent.ecosystem)) == 1)
        .subquery()
    )
    eco_col = func.coalesce(eco_sub.c.ecosystem, name_single_sub.c.sole_eco, "")

    # Count findings by severity per ecosystem
    finding_counts = (
        select(
            eco_col.label("ecosystem"),
            func.count(Finding.id).label("total_findings"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("critical"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("high"),
            func.sum(case((Finding.severity == "medium", 1), else_=0)).label("medium"),
            func.sum(case((Finding.severity == "low", 1), else_=0)).label("low"),
            func.count(func.distinct(Finding.asset_id)).label("assets_with_findings"),
        )
        .select_from(Finding)
        .outerjoin(
            eco_sub,
            and_(
                Finding.asset_id == eco_sub.c.asset_id,
                Finding.package_name == eco_sub.c.name,
            ),
        )
        .outerjoin(name_single_sub, Finding.package_name == name_single_sub.c.name)
        .where(Finding.asset_id.in_(asset_ids), Finding.state == "open")
        .group_by(eco_col)
    )

    # Count components and assets with components per ecosystem
    component_counts = (
        select(
            SbomComponent.ecosystem,
            func.count(SbomComponent.id).label("total_components"),
            func.count(func.distinct(SbomComponent.asset_id)).label("assets_with_components"),
        )
        .where(SbomComponent.asset_id.in_(asset_ids))
        .group_by(SbomComponent.ecosystem)
    )

    # Combine findings and components data. Iterate the union of ecosystem keys so
    # a healthy ecosystem (components but zero open findings) still shows up — a
    # coverage view that silently drops no-finding ecosystems would read as "no
    # coverage" when it's actually the opposite.
    async def _query(session):
        finding_rows = (await session.execute(finding_counts)).fetchall()
        component_rows = (await session.execute(component_counts)).fetchall()

        finding_lookup = {
            row.ecosystem: row for row in finding_rows
        }
        component_lookup = {
            row.ecosystem: row for row in component_rows
        }

        all_ecosystems = set(finding_lookup) | set(component_lookup)
        results = []
        for eco in all_ecosystems:
            f = finding_lookup.get(eco)
            c = component_lookup.get(eco)
            results.append({
                "ecosystem": eco,
                "total_findings": f.total_findings if f else 0,
                "critical": f.critical if f else 0,
                "high": f.high if f else 0,
                "medium": f.medium if f else 0,
                "low": f.low if f else 0,
                "assets_with_findings": f.assets_with_findings if f else 0,
                "total_components": c.total_components if c else 0,
                "assets_with_components": c.assets_with_components if c else 0,
            })

        return results

    rows = run_db(_query)

    # Convert to SbomEcosystemAnalytics objects
    analytics = []
    for row in rows:
        ecosystem = row["ecosystem"] or ""
        critical = int(row["critical"] or 0)
        high = int(row["high"] or 0)
        medium = int(row["medium"] or 0)
        low = int(row["low"] or 0)

        # Calculate risk score using weighted volume formula from posture
        risk_score = (
            critical * SEVERITY_WEIGHTS["critical"]
            + high * SEVERITY_WEIGHTS["high"]
            + medium * SEVERITY_WEIGHTS["medium"]
            + low * SEVERITY_WEIGHTS["low"]
        )

        # Calculate coverage percentage
        assets_with_components = int(row["assets_with_components"] or 0)
        coverage_pct = (assets_with_components / total_assets * 100.0) if total_assets > 0 else 0.0

        analytics.append(SbomEcosystemAnalytics(
            ecosystem=ecosystem,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            total_findings=int(row["total_findings"] or 0),
            total_components=int(row["total_components"] or 0),
            assets_with_components=assets_with_components,
            assets_with_findings=int(row["assets_with_findings"] or 0),
            coverage_percentage=coverage_pct,
            risk_score=risk_score,
        ))

    return analytics

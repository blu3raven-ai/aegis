"""Polymorphic asset queries over the Asset table."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Asset, Finding, ScanRun, Sbom, SbomComponent
from src.images.service import list_images as _list_image_rows
from src.shared.archived_filter import exclude_archived

_REPO_SCANNER_TYPES = ("dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning")
_FRESH_WINDOW_DAYS = 7


# ── Internal dataclasses (router converts to Pydantic at the edge) ──────────


@dataclass
class _CommonView:
    asset_id: str
    display_name: str | None
    last_scanned_at: datetime | None
    finding_counts: dict[str, int]


@dataclass
class RepoView(_CommonView):
    last_scanned_sha: str | None = None
    manifest_set_hash: str | None = None
    scanners_with_coverage: list[str] = field(default_factory=list)
    coverage_status: str = "never"
    source_url: str | None = None
    # True count of open findings across all severities (the severity buckets in
    # finding_counts keep only critical/high/medium/low for the pill).
    open_finding_count: int = 0


@dataclass
class ImageView(_CommonView):
    image_digest: str | None = None
    image_name: str | None = None
    image_tag: str | None = None
    layer_count: int | None = None
    size_bytes: int | None = None
    base_os: str | None = None
    repos: list[str] = field(default_factory=list)


@dataclass
class ScanRunView:
    scan_id: str
    scanner_type: str
    status: str
    started_at: str
    duration_ms: int | None
    findings_count: int


@dataclass
class FindingView:
    id: int
    tool: str
    severity: str | None
    state: str
    identity_key: str
    asset_id: str | None
    first_seen_at: str
    last_seen_at: str


@dataclass
class RepoDetailView(RepoView):
    scan_history: list[ScanRunView] = field(default_factory=list)
    active_findings: list[FindingView] = field(default_factory=list)
    default_branch: str | None = None


@dataclass
class ImageDetailView(ImageView):
    scan_history: list[ScanRunView] = field(default_factory=list)
    active_findings: list[FindingView] = field(default_factory=list)


@dataclass
class CoverageSummary:
    """Coverage KPI counts over the caller's FULL repo scope (not the page), so
    the Fresh/Stale/Never strip is accurate even when the list is capped."""
    total: int = 0
    fresh: int = 0
    stale: int = 0
    never: int = 0


@dataclass
class RepoListResult:
    sources: list[RepoView]
    next_cursor: str | None = None
    total_count: int | None = None
    coverage_summary: CoverageSummary | None = None


@dataclass
class ImageListResult:
    sources: list[ImageView]
    next_cursor: str | None = None
    total_count: int | None = None


# ── Helpers ─────────────────────────────────────────────────────────────────


def _coverage_status(last_scanned_at: datetime | None) -> str:
    if last_scanned_at is None:
        return "never"
    cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS)
    return "fresh" if last_scanned_at >= cutoff else "stale"


async def _repo_coverage_summary(
    session: AsyncSession, asset_ids: list[str]
) -> CoverageSummary:
    """Coverage counts over the caller's FULL repo scope (no page limit), so the
    KPI strip is correct for estates larger than one page. Same definition as
    ``_coverage_status``: covered = a non-empty dependency SBOM; fresh if scanned
    within the window, else stale; never = the rest."""
    if not asset_ids:
        return CoverageSummary()
    repo_ids = select(Asset.id).where(Asset.id.in_(asset_ids), Asset.type == "repo")
    total = (
        await session.execute(select(func.count()).select_from(repo_ids.subquery()))
    ).scalar_one()
    cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS)
    row = (
        await session.execute(
            select(
                func.count().filter(Sbom.scanned_at >= cutoff).label("fresh"),
                func.count().filter(Sbom.scanned_at < cutoff).label("stale"),
            )
            .select_from(Sbom)
            .where(
                Sbom.asset_id.in_(repo_ids),
                select(SbomComponent.id)
                .where(SbomComponent.asset_id == Sbom.asset_id)
                .exists(),
            )
        )
    ).one()
    fresh, stale = row.fresh or 0, row.stale or 0
    return CoverageSummary(total=total, fresh=fresh, stale=stale, never=total - fresh - stale)


async def _dependency_sbom_scanned(
    session: AsyncSession, asset_ids: list[str]
) -> dict[str, datetime]:
    """Map asset_id → SBOM ``scanned_at`` for assets with a non-empty dependency
    SBOM. Coverage means "a dependency-scan SBOM exists" (the SBOM page's
    definition), read from the per-asset ``Sbom`` table — org-level "Scan now"
    runs leave ``ScanRun.asset_id`` NULL, so ScanRun can't answer this and a
    real SBOM otherwise reads "never". Empty SBOMs (no components) are excluded
    so the coverage badge agrees with the detail page's empty state."""
    if not asset_ids:
        return {}
    stmt = (
        select(Sbom.asset_id, Sbom.scanned_at)
        .where(Sbom.asset_id.in_(asset_ids))
        .where(
            select(SbomComponent.id)
            .where(SbomComponent.asset_id == Sbom.asset_id)
            .exists()
        )
    )
    return {aid: ts for aid, ts in (await session.execute(stmt)).all()}


async def _open_finding_tools(
    session: AsyncSession, asset_ids: list[str]
) -> dict[str, set[str]]:
    """Map asset_id → the set of scanner tools that have at least one open
    finding on the asset (used to report which scanners have coverage, since the
    org-level ScanRun envelopes aren't asset-linked)."""
    if not asset_ids:
        return {}
    stmt = exclude_archived(
        select(Finding.asset_id, Finding.tool)
        .where(Finding.asset_id.in_(asset_ids))
        .where(Finding.state == "open")
        .distinct(),
        Finding,
    )
    out: dict[str, set[str]] = {}
    for aid, tool in (await session.execute(stmt)).all():
        out.setdefault(aid, set()).add(tool)
    return out


def _scanners_with_coverage(finding_tools: set[str], has_sbom: bool) -> list[str]:
    """Scanner types with evidence for the asset: any tool with an open finding,
    plus dependency scanning when a non-empty SBOM exists."""
    return [
        t
        for t in _REPO_SCANNER_TYPES
        if t in finding_tools or (t == "dependencies_scanning" and has_sbom)
    ]


def _truncate(value: str | None, length: int) -> str | None:
    return value[:length] if value else None


def _empty_counts() -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0}


def _normalize_counts(raw: dict[str, int]) -> dict[str, int]:
    return {sev: raw.get(sev, 0) for sev in ("critical", "high", "medium", "low")}


# ── Repo aggregation (moved from repos/service.py) ──────────────────────────


async def _list_repo_sources_async(
    session: AsyncSession,
    asset_ids: list[str],
    since_days: int | None,
    has_critical: bool | None,
    limit: int,
) -> list[RepoView]:
    if not asset_ids:
        return []

    since_cutoff: datetime | None = None
    if since_days:
        since_cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    stmt = (
        select(Asset)
        .where(Asset.id.in_(asset_ids))
        .where(Asset.type == "repo")
    )
    # Apply the has_critical / since filters in SQL, BEFORE the limit, so the
    # page bounds the filtered set — not the input to the filter (which would
    # silently drop matches beyond the first `limit` most-recent repos).
    if has_critical is True:
        stmt = stmt.where(
            Asset.id.in_(
                exclude_archived(
                    select(Finding.asset_id)
                    .where(Finding.state == "open")
                    .where(Finding.severity == "critical"),
                    Finding,
                )
            )
        )
    if since_cutoff is not None:
        # `since` is dependency-scan freshness — a fresh, non-empty SBOM.
        stmt = stmt.where(
            Asset.id.in_(
                select(Sbom.asset_id)
                .where(Sbom.scanned_at >= since_cutoff)
                .where(
                    select(SbomComponent.id)
                    .where(SbomComponent.asset_id == Sbom.asset_id)
                    .exists()
                )
            )
        )
    stmt = stmt.order_by(Asset.updated_at.desc()).limit(limit)
    assets = (await session.execute(stmt)).scalars().all()
    if not assets:
        return []

    repo_asset_ids = [a.id for a in assets]

    # Coverage = a non-empty dependency-scan SBOM exists for the asset. Read it
    # from the per-asset Sbom table (every dependency scan upserts one), not from
    # ScanRun: org-level "Scan now" runs leave ScanRun.asset_id NULL, so a real
    # SBOM would otherwise read "never". Freshness is the SBOM's scanned_at.
    sbom_scanned_map = await _dependency_sbom_scanned(session, repo_asset_ids)
    finding_tools_map = await _open_finding_tools(session, repo_asset_ids)

    finding_counts_stmt = exclude_archived(
        select(Finding.asset_id, Finding.severity, func.count(Finding.id).label("cnt"))
        .where(Finding.asset_id.in_(repo_asset_ids))
        .where(Finding.state == "open")
        .group_by(Finding.asset_id, Finding.severity),
        Finding,
    )
    finding_map: dict[str, dict[str, int]] = {}
    for asset_id, severity, cnt in (await session.execute(finding_counts_stmt)).all():
        finding_map.setdefault(asset_id, {})[severity or "unknown"] = cnt

    out: list[RepoView] = []
    for a in assets:
        last_scanned_at = sbom_scanned_map.get(a.id)
        scanners = _scanners_with_coverage(
            finding_tools_map.get(a.id, set()), has_sbom=last_scanned_at is not None
        )
        raw_counts = finding_map.get(a.id, {})
        counts = _normalize_counts(raw_counts)
        # True open-finding total across ALL severities, so a repo whose findings
        # carry a NULL/non-canonical severity isn't shown as "0 findings" (the
        # severity buckets keep only critical/high/medium/low for the pill).
        open_finding_count = sum(raw_counts.values())

        out.append(RepoView(
            asset_id=a.id,
            display_name=a.display_name,
            last_scanned_at=last_scanned_at,
            finding_counts=counts,
            open_finding_count=open_finding_count,
            last_scanned_sha=_truncate(a.last_scanned_sha, 7),
            manifest_set_hash=_truncate(a.manifest_set_hash, 8),
            scanners_with_coverage=scanners,
            coverage_status=_coverage_status(last_scanned_at),
        ))

    return out


async def _get_repo_detail_async(
    session: AsyncSession,
    asset: Asset,
) -> RepoDetailView:
    history_rows = (await session.execute(
        select(ScanRun)
        .where(ScanRun.asset_id == asset.id)
        .order_by(ScanRun.started_at.desc().nullslast())
        .limit(10)
    )).scalars().all()

    scan_history: list[ScanRunView] = []
    for r in history_rows:
        duration_ms = None
        if r.started_at and r.finished_at:
            duration_ms = int((r.finished_at - r.started_at).total_seconds() * 1000)
        fc = (r.metadata_json or {}).get("findings_count", 0)
        scan_history.append(ScanRunView(
            scan_id=r.id,
            scanner_type=r.tool,
            status=r.status,
            started_at=r.started_at.isoformat() if r.started_at else "",
            duration_ms=duration_ms,
            findings_count=fc,
        ))

    findings_rows = (await session.execute(
        exclude_archived(
            select(Finding)
            .where(and_(Finding.asset_id == asset.id, Finding.state == "open"))
            .order_by(Finding.first_seen_at.desc())
            .limit(50),
            Finding,
        )
    )).scalars().all()
    active_findings = [
        FindingView(
            id=f.id, tool=f.tool, severity=f.severity, state=f.state,
            identity_key=f.identity_key, asset_id=f.asset_id,
            first_seen_at=f.first_seen_at.isoformat(),
            last_seen_at=f.last_seen_at.isoformat(),
        )
        for f in findings_rows
    ]

    # Coverage from the same per-asset SBOM source as the list view, so a repo's
    # card and its detail page never disagree (the scan_history above is only the
    # display list, not the coverage source).
    last_scanned_at = (await _dependency_sbom_scanned(session, [asset.id])).get(asset.id)
    finding_tools = (await _open_finding_tools(session, [asset.id])).get(asset.id, set())
    scanners = _scanners_with_coverage(finding_tools, has_sbom=last_scanned_at is not None)

    sev_raw = {
        row[0] or "unknown": row[1]
        for row in (await session.execute(
            exclude_archived(
                select(Finding.severity, func.count(Finding.id))
                .where(and_(Finding.asset_id == asset.id, Finding.state == "open"))
                .group_by(Finding.severity),
                Finding,
            )
        )).all()
    }
    counts = _normalize_counts(sev_raw)

    return RepoDetailView(
        asset_id=asset.id,
        display_name=asset.display_name,
        last_scanned_at=last_scanned_at,
        finding_counts=counts,
        last_scanned_sha=_truncate(asset.last_scanned_sha, 7),
        manifest_set_hash=_truncate(asset.manifest_set_hash, 8),
        scanners_with_coverage=scanners,
        coverage_status=_coverage_status(last_scanned_at),
        scan_history=scan_history,
        active_findings=active_findings,
    )


# ── Image aggregation (delegates to images/service) ─────────────────────────


async def list_image_sources(
    asset_ids: list[str],
    cursor: str | None = None,
    limit: int = 50,
) -> ImageListResult:
    """Return container-image sources for the caller's scope, with cursor pagination."""
    result = await _list_image_rows(asset_ids=asset_ids, cursor=cursor, limit=limit)
    sources = [
        ImageView(
            asset_id=row.image_digest,  # images use digest as their stable id
            display_name=row.image_name,
            last_scanned_at=row.last_scanned_at,
            finding_counts={"critical": row.critical, "high": row.high, "medium": row.medium, "low": row.low},
            image_digest=row.image_digest,
            image_name=row.image_name,
            image_tag=row.image_tag,
            layer_count=row.layer_count,
            size_bytes=row.size_bytes,
            base_os=row.base_os,
            repos=row.repos,
        )
        for row in result.images
    ]
    return ImageListResult(sources=sources, next_cursor=result.next_cursor, total_count=result.total_count)


async def _get_image_detail_async(
    session: AsyncSession,
    asset: Asset,
) -> ImageDetailView:
    history_rows = (await session.execute(
        select(ScanRun)
        .where(ScanRun.asset_id == asset.id)
        .order_by(ScanRun.started_at.desc().nullslast())
        .limit(10)
    )).scalars().all()

    scan_history: list[ScanRunView] = []
    for r in history_rows:
        duration_ms = None
        if r.started_at and r.finished_at:
            duration_ms = int((r.finished_at - r.started_at).total_seconds() * 1000)
        fc = (r.metadata_json or {}).get("findings_count", 0)
        scan_history.append(ScanRunView(
            scan_id=r.id,
            scanner_type=r.tool,
            status=r.status,
            started_at=r.started_at.isoformat() if r.started_at else "",
            duration_ms=duration_ms,
            findings_count=fc,
        ))

    findings_rows = (await session.execute(
        exclude_archived(
            select(Finding)
            .where(and_(Finding.asset_id == asset.id, Finding.state == "open"))
            .order_by(Finding.first_seen_at.desc())
            .limit(50),
            Finding,
        )
    )).scalars().all()
    active_findings = [
        FindingView(
            id=f.id, tool=f.tool, severity=f.severity, state=f.state,
            identity_key=f.identity_key, asset_id=f.asset_id,
            first_seen_at=f.first_seen_at.isoformat(),
            last_seen_at=f.last_seen_at.isoformat(),
        )
        for f in findings_rows
    ]

    # Extract image-specific extras from the most recent container_scanning finding.
    latest_image_finding = (await session.execute(
        select(Finding.detail)
        .where(and_(Finding.asset_id == asset.id, Finding.tool == "container_scanning"))
        .order_by(Finding.last_seen_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    image_extras: dict[str, Any] = {}
    if latest_image_finding:
        image_extras = {
            "image_digest": latest_image_finding.get("imageDigest"),
            "image_name": latest_image_finding.get("imageName"),
            "image_tag": latest_image_finding.get("imageTag"),
            "layer_count": latest_image_finding.get("layerCount"),
            "size_bytes": latest_image_finding.get("sizeBytes"),
            "base_os": latest_image_finding.get("baseOs"),
        }

    last_scanned_at = max(
        (r.finished_at for r in history_rows if r.status == "completed" and r.finished_at),
        default=None,
    )

    sev_raw = {
        row[0] or "unknown": row[1]
        for row in (await session.execute(
            exclude_archived(
                select(Finding.severity, func.count(Finding.id))
                .where(and_(Finding.asset_id == asset.id, Finding.state == "open"))
                .group_by(Finding.severity),
                Finding,
            )
        )).all()
    }

    return ImageDetailView(
        asset_id=asset.id,
        display_name=asset.display_name,
        last_scanned_at=last_scanned_at,
        finding_counts=_normalize_counts(sev_raw),
        scan_history=scan_history,
        active_findings=active_findings,
        **image_extras,
    )


# ── Public dispatchers ──────────────────────────────────────────────────────


def list_repo_sources(
    asset_ids: list[str],
    since_days: int | None = None,
    has_critical: bool | None = None,
    limit: int = 100,
) -> RepoListResult:
    """Return repository sources for the caller's scope. Sync wrapper around the async loader."""
    async def _run(session: AsyncSession) -> RepoListResult:
        sources = await _list_repo_sources_async(session, asset_ids, since_days, has_critical, min(limit, 500))
        # Coverage counts + true in-scope repo count over the FULL scope (not the
        # capped page), so the KPI strip and "showing first N of M" are honest for
        # estates larger than one page. total_count == coverage_summary.total.
        coverage = await _repo_coverage_summary(session, asset_ids)
        return RepoListResult(
            sources=sources,
            next_cursor=None,
            total_count=coverage.total,
            coverage_summary=coverage,
        )
    return run_db(_run)


async def get_source(asset_id: str, asset_ids: list[str]) -> RepoDetailView | ImageDetailView | None:
    """Polymorphic detail lookup. Returns None if asset is out of scope or absent."""
    if not asset_ids or asset_id not in asset_ids:
        return None

    from src.db.engine import get_session
    async with get_session() as session:
        asset = (await session.execute(
            select(Asset).where(Asset.id == asset_id)
        )).scalar_one_or_none()
        if asset is None:
            return None

        if asset.type == "repo":
            return await _get_repo_detail_async(session, asset)
        if asset.type == "image":
            return await _get_image_detail_async(session, asset)
        if asset.type == "cloud":
            # Schema reserves cloud as a valid type; no detail loader wired yet.
            return None
        return None

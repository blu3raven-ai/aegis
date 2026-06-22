"""Sources GraphQL resolvers.

Thin wrappers around src/sources/service.py and src/sources/store.py.
Business logic stays in the service layer; this module owns shape conversion
to the Strawberry types declared in src/graphql/types.py.
"""
from __future__ import annotations

from typing import Any, Optional

from graphql import GraphQLError

from src.authz.enforcement import has_permission
from src.authz.permissions.catalog import VIEW_FINDINGS
from src.graphql.resolver_utils import raise_permission_denied
from src.graphql.types import (
    ImageSourcesResponse,
    RepoSourcesResponse,
    SourceDetail,
    SourceFindingCounts,
    SourceFindingRow,
    SourceImageDetail,
    SourceImageExtras,
    SourceImageSummary,
    SourceRepoDetail,
    SourceRepoExtras,
    SourceRepoSummary,
    SourceScanRunRow,
)
from src.sources import store as sources_store
from src.sources.service import (
    ImageDetailView,
    ImageView,
    RepoDetailView,
    RepoView,
    ScanRunView,
    FindingView,
    get_source as _get_source,
    list_image_sources as _list_image_sources,
    list_repo_sources as _list_repo_sources,
)


def _require_request(info_context: dict[str, Any]):
    request = info_context.get("request") if info_context else None
    if request is None:
        raise_permission_denied("Unauthorized")
    return request


def _require_view_findings(info_context: dict[str, Any]) -> None:
    """Permission gate for finding-aggregated source views.

    These resolvers expose finding counts + severity rollups per source
    asset; the right gate is view_findings (not view_sources, which covers
    source-connection config under /api/v1/sources/connections/* — a
    different surface).
    """
    request = _require_request(info_context)
    if not has_permission(request, VIEW_FINDINGS):
        raise_permission_denied("Permission denied: view_findings")


# ── Adapters: service dataclass → Strawberry type ───────────────────────────


def _counts(raw: dict[str, int]) -> SourceFindingCounts:
    return SourceFindingCounts(
        critical=int(raw.get("critical", 0) or 0),
        high=int(raw.get("high", 0) or 0),
        medium=int(raw.get("medium", 0) or 0),
        low=int(raw.get("low", 0) or 0),
    )


def _repo_extras(v: RepoView) -> SourceRepoExtras:
    return SourceRepoExtras(
        last_scanned_sha=v.last_scanned_sha,
        manifest_set_hash=v.manifest_set_hash,
        scanners_with_coverage=list(v.scanners_with_coverage or []),
        coverage_status=v.coverage_status,
        source_url=v.source_url,
    )


def _image_extras(v: ImageView) -> SourceImageExtras:
    return SourceImageExtras(
        image_digest=v.image_digest,
        image_name=v.image_name,
        image_tag=v.image_tag,
        layer_count=v.layer_count,
        size_bytes=v.size_bytes,
        base_os=v.base_os,
        repos=list(v.repos or []),
    )


def _scan_runs(items: list[ScanRunView]) -> list[SourceScanRunRow]:
    return [
        SourceScanRunRow(
            scan_id=r.scan_id,
            scanner_type=r.scanner_type,
            status=r.status,
            started_at=r.started_at,
            duration_ms=r.duration_ms,
            findings_count=r.findings_count,
        )
        for r in items
    ]


def _findings(items: list[FindingView]) -> list[SourceFindingRow]:
    return [
        SourceFindingRow(
            id=f.id,
            tool=f.tool,
            severity=f.severity,
            state=f.state,
            identity_key=f.identity_key,
            asset_id=f.asset_id,
            first_seen_at=f.first_seen_at,
            last_seen_at=f.last_seen_at,
        )
        for f in items
    ]


def _repo_summary(v: RepoView) -> SourceRepoSummary:
    return SourceRepoSummary(
        type="repo",
        asset_id=v.asset_id,
        display_name=v.display_name,
        last_scanned_at=v.last_scanned_at.isoformat() if v.last_scanned_at else None,
        finding_counts=_counts(v.finding_counts),
        repo=_repo_extras(v),
    )


def _image_summary(v: ImageView) -> SourceImageSummary:
    return SourceImageSummary(
        type="image",
        asset_id=v.asset_id,
        display_name=v.display_name,
        last_scanned_at=v.last_scanned_at.isoformat() if v.last_scanned_at else None,
        finding_counts=_counts(v.finding_counts),
        image=_image_extras(v),
    )


def _repo_detail(v: RepoDetailView) -> SourceRepoDetail:
    return SourceRepoDetail(
        type="repo",
        asset_id=v.asset_id,
        display_name=v.display_name,
        last_scanned_at=v.last_scanned_at.isoformat() if v.last_scanned_at else None,
        finding_counts=_counts(v.finding_counts),
        repo=_repo_extras(v),
        scan_history=_scan_runs(v.scan_history),
        active_findings=_findings(v.active_findings),
        default_branch=v.default_branch,
    )


def _image_detail(v: ImageDetailView) -> SourceImageDetail:
    return SourceImageDetail(
        type="image",
        asset_id=v.asset_id,
        display_name=v.display_name,
        last_scanned_at=v.last_scanned_at.isoformat() if v.last_scanned_at else None,
        finding_counts=_counts(v.finding_counts),
        image=_image_extras(v),
        scan_history=_scan_runs(v.scan_history),
        active_findings=_findings(v.active_findings),
    )


# ── Resolvers ───────────────────────────────────────────────────────────────


def repo_sources(
    *,
    asset_ids: list[str],
    info_context: dict[str, Any],
    since_days: Optional[int] = None,
    has_critical: Optional[bool] = None,
    limit: int = 100,
) -> RepoSourcesResponse:
    """Finding-aggregated list of repo source assets in the caller's scope."""
    _require_view_findings(info_context)
    result = _list_repo_sources(
        asset_ids=asset_ids,
        since_days=since_days,
        has_critical=has_critical,
        limit=limit,
    )
    return RepoSourcesResponse(
        sources=[_repo_summary(v) for v in result.sources],
        next_cursor=result.next_cursor,
        total_count=result.total_count,
    )


async def image_sources(
    *,
    asset_ids: list[str],
    info_context: dict[str, Any],
    cursor: Optional[str] = None,
    limit: int = 50,
) -> ImageSourcesResponse:
    """Finding-aggregated list of container-image source assets in scope."""
    _require_view_findings(info_context)
    if limit < 1 or limit > 200:
        raise GraphQLError(
            "limit must be between 1 and 200",
            extensions={"code": "VALIDATION_ERROR"},
        )
    try:
        result = await _list_image_sources(asset_ids=asset_ids, cursor=cursor, limit=limit)
    except ValueError as e:
        raise GraphQLError(str(e), extensions={"code": "VALIDATION_ERROR"}) from e
    return ImageSourcesResponse(
        sources=[_image_summary(v) for v in result.sources],
        next_cursor=result.next_cursor,
        total_count=result.total_count,
    )


async def source(
    *,
    asset_id: str,
    asset_ids: list[str],
    info_context: dict[str, Any],
) -> Optional[SourceDetail]:
    """Detail view of a single source asset, polymorphic repo|image."""
    _require_view_findings(info_context)
    view = await _get_source(asset_id=asset_id, asset_ids=asset_ids)
    if view is None:
        return None
    if isinstance(view, RepoDetailView):
        return _repo_detail(view)
    if isinstance(view, ImageDetailView):
        return _image_detail(view)
    return None



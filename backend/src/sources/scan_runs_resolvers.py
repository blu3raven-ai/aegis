"""GraphQL resolver for scan-run history (per scanner type).

Authorization mirrors the sibling sources resolvers:
  - VIEW_FINDINGS is required (consistency with sources.repoSources /
    sources.imageSources / sources.source).
  - The query is scoped to the caller's accessible asset_ids — runs whose
    asset_id is not in the user's grant set are not returned.

The old org-key derivation (asset_ids → owner_segments → fetch all runs
in those orgs) returned every run for every repo in any org touched by
the caller's scope, leaking activity across asset boundaries within an
org. The replacement query filters on ScanRun.asset_id directly.
"""
from __future__ import annotations

from typing import Any, Optional

import strawberry
from sqlalchemy import select

from src.db.helpers import run_db
from src.sources.resolvers import _require_view_findings
from src.storage import _run_to_dict


_SUPPORTED_TOOLS = frozenset({
    "code_scanning",
    "container_scanning",
    "dependencies_scanning",
    "secret_scanning",
})


@strawberry.type
class ScanRun:
    id: str
    org: str
    status: str
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    duration_seconds: Optional[int]
    findings_count: int
    error: Optional[str]


def _to_strawberry(run: dict[str, Any]) -> "ScanRun":
    return ScanRun(
        id=str(run.get("id") or ""),
        org=str(run.get("org") or ""),
        status=str(run.get("status") or "queued"),
        created_at=str(run.get("createdAt") or ""),
        started_at=run.get("startedAt"),
        finished_at=run.get("finishedAt"),
        duration_seconds=run.get("durationSeconds"),
        findings_count=int(run.get("findingsCount") or 0),
        error=run.get("error"),
    )


def _list_runs_for_assets(tool: str, asset_ids: list[str], *, limit: int) -> list[dict[str, Any]]:
    """Query ScanRun rows for a tool, scoped to the caller's asset_ids.

    Replaces the legacy ``list_<tool>_runs(org_key)`` + dedupe pattern that
    returned runs for every asset under an org, not just the caller's
    asset set.
    """
    if not asset_ids:
        return []

    # Imported inside the function so the SQLAlchemy ``ScanRun`` name does
    # not collide with the Strawberry ``ScanRun`` declared at module scope.
    from src.db.models import ScanRun as ScanRunModel

    async def _query(session):
        result = await session.execute(
            select(ScanRunModel)
            .where(ScanRunModel.tool == tool)
            .where(ScanRunModel.asset_id.in_(asset_ids))
            .order_by(ScanRunModel.started_at.desc().nullslast())
            .limit(max(1, min(50, limit)))
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


async def scan_runs(*, tool: str, limit: int, info_context: dict) -> list["ScanRun"]:
    _require_view_findings(info_context)
    if tool not in _SUPPORTED_TOOLS:
        return []
    asset_ids = info_context.get("asset_ids") or []
    if not asset_ids:
        return []
    runs = _list_runs_for_assets(tool, asset_ids, limit=limit)
    return [_to_strawberry(r) for r in runs]


@strawberry.type
class ConnectionScanRun:
    """One scan run under a source connection, carrying the asset + scanner it
    ran for so a connection that fans out to many assets stays legible."""
    scan_id: str
    asset_id: str
    asset_name: str
    scanner_type: str
    status: str
    started_at: Optional[str]
    finished_at: Optional[str]
    duration_ms: Optional[int]
    findings_count: int
    error: Optional[str]


def _list_connection_runs(
    connection_id: str, asset_ids: list[str], *, limit: int
) -> list["ConnectionScanRun"]:
    """Scan runs across every asset a connection discovered, newest first.

    BOLA: the connection's assets are intersected with the caller's accessible
    asset_ids at the SQL layer — a run on an asset outside the caller's grants
    is never returned.
    """
    if not asset_ids:
        return []

    from src.db.models import Asset, ScanRun as ScanRunModel

    async def _query(session):
        scoped = (await session.execute(
            select(Asset.id, Asset.display_name)
            .where(Asset.source == "source_connection")
            .where(Asset.source_ref == connection_id)
            .where(Asset.id.in_(asset_ids))
        )).all()
        if not scoped:
            return []
        names = {str(aid): (name or "") for aid, name in scoped}

        rows = (await session.execute(
            select(ScanRunModel)
            .where(ScanRunModel.asset_id.in_(list(names.keys())))
            .order_by(ScanRunModel.started_at.desc().nullslast())
            .limit(max(1, min(200, limit)))
        )).scalars().all()

        out: list[ConnectionScanRun] = []
        for r in rows:
            duration_ms = None
            if r.started_at and r.finished_at:
                duration_ms = int((r.finished_at - r.started_at).total_seconds() * 1000)
            fc = (r.metadata_json or {}).get("findings_count", 0)
            out.append(ConnectionScanRun(
                scan_id=r.id,
                asset_id=str(r.asset_id or ""),
                asset_name=names.get(str(r.asset_id), ""),
                scanner_type=r.tool,
                status=r.status,
                started_at=r.started_at.isoformat() if r.started_at else None,
                finished_at=r.finished_at.isoformat() if r.finished_at else None,
                duration_ms=duration_ms,
                findings_count=int(fc or 0),
                error=r.error,
            ))
        return out

    return run_db(_query)


async def connection_scan_runs(
    *, connection_id: str, limit: int, info_context: dict
) -> list["ConnectionScanRun"]:
    _require_view_findings(info_context)
    asset_ids = info_context.get("asset_ids") or []
    if not asset_ids:
        return []
    return _list_connection_runs(connection_id, asset_ids, limit=limit)

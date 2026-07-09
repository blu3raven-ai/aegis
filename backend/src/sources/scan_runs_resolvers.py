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
from src.sources import store as sources_store
from src.sources.resolvers import _require_view_findings
from src.sources.store import SourceNotFoundError
from src.storage import _run_to_dict


# Every user-selectable scanner produces run records the Scans tab must show.
# Derived from the canonical set (not a hand-maintained copy) so a newly added
# scanner — iac, agent, and future ones — can't be silently dropped from the list.
from src.scans.models import _VALID_SCANNERS

_SUPPORTED_TOOLS = frozenset(_VALID_SCANNERS)


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
    """Scan runs for a source connection, newest first.

    Two run shapes surface here, both gated on the caller holding scope on the
    connection (at least one in-scope asset under the connection's org):

      * Asset-bound runs (CI / BYO / pre-release) carry a real ``asset_id`` —
        intersected with the caller's accessible ``asset_ids`` at the SQL layer
        so a run on an out-of-grant asset is never returned.
      * Connection-level runs from "Scan now" / scheduled syncs fan out across
        every discovered repo in a single job and are born with ``asset_id``
        NULL, keyed only by ``org_label``. Matching them on asset_id alone
        silently drops them, leaving the tab empty even after the scan finishes
        — so they are matched by run-id prefix + org_label (mirroring the
        active-scan banner) once the caller's connection scope is established.

    The connection→asset link is the asset's ``external_ref`` owner, not
    ``source_ref``: source-connection discovery never stamps ``source_ref``
    (it stays NULL), so the owner segment of the canonical external_ref is the
    only durable tie back to the connection's org — the same signal the Findings
    tab scopes on. Owner matching also spans repos and images uniformly.
    """
    if not asset_ids:
        return []

    from sqlalchemy import and_, func, or_
    from src.assets.refs import owner_from_external_ref
    from src.db.models import Asset, ScanRun as ScanRunModel

    org_label = ""
    try:
        conn = sources_store.get_connection(connection_id)
        org_label = ((conn.get("auth") or {}).get("orgOrOwner") or "").strip()
    except SourceNotFoundError:
        org_label = ""

    if not org_label:
        # Without the connection's org we cannot tie any asset or org-level run
        # back to it — fail closed.
        return []

    async def _query(session):
        # BOLA is enforced in SQL via ``id.in_(asset_ids)`` — only the caller's
        # granted assets are loaded. Narrowing those to the connection's org by
        # external_ref owner is a refinement on an already-scoped set, never the
        # scope boundary itself.
        candidates = (await session.execute(
            select(Asset.id, Asset.display_name, Asset.external_ref)
            .where(Asset.source == "source_connection")
            .where(Asset.id.in_(asset_ids))
        )).all()
        names: dict[str, str] = {}
        for aid, name, external_ref in candidates:
            try:
                owner = owner_from_external_ref(external_ref or "")
            except ValueError:
                continue
            if owner.lower() == org_label.lower():
                names[str(aid)] = name or ""
        if not names:
            # No in-scope asset under this connection's org → caller has no
            # scope on the connection; show nothing (incl. org-level runs).
            return []

        clause = or_(
            ScanRunModel.asset_id.in_(list(names.keys())),
            and_(
                or_(
                    ScanRunModel.id.like("manual-%"),
                    ScanRunModel.id.like("scheduled-%"),
                ),
                ScanRunModel.tool.in_(_SUPPORTED_TOOLS),
                func.lower(ScanRunModel.metadata_json["org_label"].astext)
                == org_label.lower(),
            ),
        )

        rows = (await session.execute(
            select(ScanRunModel)
            .where(clause)
            .order_by(ScanRunModel.started_at.desc().nullslast())
            .limit(max(1, min(200, limit)))
        )).scalars().all()

        out: list[ConnectionScanRun] = []
        for r in rows:
            duration_ms = None
            if r.started_at and r.finished_at:
                duration_ms = int((r.finished_at - r.started_at).total_seconds() * 1000)
            meta = r.metadata_json or {}
            fc = meta.get("findingsCount", meta.get("findings_count"))
            if fc is None:
                fc = (meta.get("counts") or {}).get("total", 0)
            aid = str(r.asset_id or "")
            out.append(ConnectionScanRun(
                scan_id=r.id,
                asset_id=aid,
                # Asset-bound runs resolve to the repo's display name; an
                # org-level fan-out run covers the whole connection.
                asset_name=names.get(aid) or "All repositories",
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

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.audit_log.decorators import audited
from src.sources import store as sources_store
from src.sources.store import (
    SourceNotFoundError,
    SourceValidationError,
    SourceStoreError,
)
from src.sources.test_connection import test_connection
from src.shared.encryption import DecryptionError
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SOURCES, VIEW_SOURCES

_DECRYPT_FAILED_MSG = (
    "Stored credentials could not be decrypted — the encryption key may have "
    "changed. Re-enter the token to reconnect."
)
source_connections_router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


def _connection_orgs(conn: dict[str, Any]) -> set[str]:
    """Lower-cased source orgs a connection scans, used to match its scan runs.

    A connection with an explicit ``orgOrOwner`` scans exactly that org.
    Cherry-pick / multi-org PAT connections carry no single ``orgOrOwner``, so
    fall back to the org prefixes of their discovered repo full-names
    ("owner/repo" -> "owner") — without this, such a connection's active runs
    never group back to it and its progress banner never appears.
    """
    org = ((conn.get("auth") or {}).get("orgOrOwner") or "").strip()
    if org:
        return {org.lower()}
    return {
        item.split("/", 1)[0].strip().lower()
        for item in (conn.get("discoveredItems") or [])
        if isinstance(item, str) and "/" in item
    } - {""}


# Pydantic models


class CreateConnectionRequest(BaseModel):
    category: str
    sourceType: str
    name: str
    auth: dict
    scanScope: str = "all"
    excludedItems: list[str] = []
    includedItems: list[str] = []
    scanners: list[str] = []
    connectionMethods: list[str] = []
    syncSchedule: str = "1h"


class UpdateConnectionRequest(BaseModel):
    auth: dict | None = None
    scanScope: str | None = None
    excludedItems: list[str] | None = None
    includedItems: list[str] | None = None
    scanners: list[str] | None = None
    syncSchedule: str | None = None
    syncScheduleMode: str | None = None
    syncScheduleCron: str | None = None
    scanAutoEnabled: bool | None = None
    scanScheduleMode: str | None = None
    scanSchedulePreset: str | None = None
    scanScheduleCron: str | None = None


class TestNewConnectionRequest(BaseModel):
    sourceType: str
    auth: dict


class CancelScanRequest(BaseModel):
    run_ids: list[str]


class ValidateRepoUrlRequest(BaseModel):
    url: str


# Helpers


def _serialize_connection(c: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw source-connection dict from the store into REST response shape."""
    auth = c.get("auth") or {}
    return {
        "id": str(c.get("id", "")),
        "sourceType": str(c.get("sourceType", "")),
        "category": str(c.get("category", "")),
        "name": str(c.get("name", "")),
        "status": str(c.get("status", "")),
        "auth": {
            "orgOrOwner": str(auth.get("orgOrOwner", "")),
            "username": auth.get("username"),
            "instanceUrl": auth.get("instanceUrl"),
            "groupOrProject": auth.get("groupOrProject"),
        },
        "scanScope": str(c.get("scanScope", "all") or "all"),
        "excludedItems": list(c.get("excludedItems") or []),
        "includedItems": list(c.get("includedItems") or []),
        "syncSchedule": c.get("syncSchedule"),
        "statusMessage": c.get("statusMessage"),
        "lastSyncedAt": c.get("lastSyncedAt"),
        "lastScanAt": c.get("lastScanAt"),
        "nextSyncAt": c.get("nextSyncAt"),
        "findingCounts": c.get("findingCounts") or {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "discoveredItemCount": c.get("discoveredItemCount"),
        "discoveredItems": list(c.get("discoveredItems") or []),
        "createdAt": c.get("createdAt"),
        "updatedAt": c.get("updatedAt"),
    }


def _json_error(error: Any, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": str(error)}, status_code=status_code)


# Endpoints


@source_connections_router.post("/connections/test-new")
async def post_test_new_connection(
    body: TestNewConnectionRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    try:
        result = await test_connection(body.sourceType, body.auth)
        return JSONResponse(result.to_dict())
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.post("/connections/validate-repo-url")
async def post_validate_repo_url(
    body: ValidateRepoUrlRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    """Existence check for a self-hosted repo URL (SSRF-hardened; admin only)."""
    from src.sources.repo_url_check import repo_url_exists

    try:
        exists = await repo_url_exists(body.url)
        return JSONResponse({"exists": exists})
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)


@source_connections_router.post("/connections", status_code=201)
@audited(action="source_connection.created", resource_type="source_connection")
def post_source(
    body: CreateConnectionRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    try:
        # License: enforce source connection limit
        from src.license.limits import check_limit
        current_count = len(sources_store.list_connections())
        check_limit(request, "max_source_connections", current_count)
        connection = sources_store.create_connection(body.model_dump())
        return JSONResponse({"connection": connection}, status_code=201)
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


# Starlette matches routes in declaration order — every literal sub-path
# (/connections, /connections/counts, /connections/internal-orgs) MUST be
# declared before the parameterized /connections/{connection_id} route,
# otherwise "internal-orgs" gets parsed as a connection id.
@source_connections_router.get("/connections")
def get_connections(
    request: Request,
    category: Optional[str] = Query(default=None),
    _: None = Depends(Permission(VIEW_SOURCES)),
) -> JSONResponse:
    try:
        connections = sources_store.list_connections(category=category)
        return JSONResponse({"connections": [_serialize_connection(c) for c in connections]})
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.get("/connections/counts")
def get_connection_counts(
    request: Request,
    _: None = Depends(Permission(VIEW_SOURCES)),
) -> JSONResponse:
    try:
        counts = sources_store.count_by_category()
        return JSONResponse(
            {"counts": [{"category": k, "count": v} for k, v in counts.items()]}
        )
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.get("/connections/internal-orgs")
def get_internal_orgs(
    request: Request,
    _: None = Depends(Permission(VIEW_SOURCES)),
) -> JSONResponse:
    # Gated like its sibling connection reads: this discloses the connected
    # org/owner inventory + health, which belongs behind view_sources.
    try:
        connections = sources_store.list_connections()
        return JSONResponse({
            "connections": [
                {
                    "orgOrOwner": str((c.get("auth") or {}).get("orgOrOwner", "")),
                    "sourceType": str(c.get("sourceType", "")),
                    "category": str(c.get("category", "")),
                    "status": str(c.get("status", "")),
                }
                for c in connections
            ]
        })
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.get("/connections/{connection_id}")
def get_source(
    connection_id: str,
    request: Request,
    _: None = Depends(Permission(VIEW_SOURCES)),
) -> JSONResponse:
    try:
        conn = sources_store.get_connection(connection_id)
        return JSONResponse({"connection": conn})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.put("/connections/{connection_id}")
@audited(action="source_connection.updated", resource_type="source_connection",
         resource_id_param="connection_id")
def put_source(
    connection_id: str,
    body: UpdateConnectionRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    try:
        # License: gate custom scan schedules (non-default) behind Pro
        if body.syncSchedule is not None and body.syncSchedule != "6h":
            from src.license.limits import check_feature
            check_feature(request, "custom_scan_schedule")
        update_data = {k: v for k, v in body.model_dump().items() if v is not None}
        connection = sources_store.update_connection(connection_id, update_data)
        return JSONResponse({"connection": connection})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.delete("/connections/{connection_id}")
@audited(action="source_connection.deleted", resource_type="source_connection",
         resource_id_param="connection_id")
def delete_source(
    connection_id: str,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    try:
        sources_store.delete_connection(connection_id)
        return JSONResponse({"ok": True})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.post("/connections/{connection_id}/test")
async def post_test_connection(
    connection_id: str,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    try:
        connection = sources_store.get_connection_with_secrets(connection_id)
        result = await test_connection(connection["sourceType"], connection["auth"])
        if result.success:
            sources_store.update_connection_status(
                connection_id,
                status="connected",
                status_message=result.message,
            )
        else:
            sources_store.update_connection_status(
                connection_id,
                status="disconnected",
                status_message=result.message,
            )
        return JSONResponse(result.to_dict())
    except DecryptionError:
        sources_store.update_connection_status(
            connection_id, status="disconnected", status_message=_DECRYPT_FAILED_MSG
        )
        return _json_error(_DECRYPT_FAILED_MSG, status_code=400)
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.post("/connections/{connection_id}/scan", status_code=202)
@audited(action="source_connection.scan_triggered", resource_type="source_connection",
         resource_id_param="connection_id")
async def post_scan_connection(
    connection_id: str,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    """Dispatch runner jobs to scan all discovered repos/images for this source connection."""
    from src.sources.triggers import dispatch_source_scan

    try:
        connection = sources_store.get_connection_with_secrets(connection_id)
        queued = dispatch_source_scan(connection, run_prefix="manual")
        return JSONResponse({"queued": queued, "count": len(queued)}, status_code=202)
    except DecryptionError:
        sources_store.update_connection_status(
            connection_id, status="disconnected", status_message=_DECRYPT_FAILED_MSG
        )
        return _json_error(_DECRYPT_FAILED_MSG, status_code=400)
    except ValueError as exc:
        return _json_error(str(exc), status_code=400)
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.get("/connections/{connection_id}/scan/active")
async def get_active_scan_runs(
    connection_id: str,
    request: Request,
    _: None = Depends(Permission(VIEW_SOURCES)),
) -> JSONResponse:
    """Return in-flight source scan runs (manual or scheduled) for this org.

    Each run carries its persisted progress snapshot (percent, repo counts,
    current repo, stage) and timing alongside its status. Clients poll this to
    reconcile the progress banner against the real run state — so a banner
    self-corrects from queued → running → done even if a live SSE progress
    event was missed, and a banner restored after a page refresh shows the real
    elapsed/percent state instead of resetting to a blank "preparing" banner.
    """
    from sqlalchemy import func, or_, select
    from src.db.engine import get_session
    from src.db.models import ScanRun

    try:
        connection = sources_store.get_connection(connection_id)
        orgs = _connection_orgs(connection)
        if not orgs:
            return JSONResponse({"runs": [], "runIds": []})

        async with get_session() as session:
            result = await session.execute(
                select(
                    ScanRun.id,
                    ScanRun.status,
                    ScanRun.progress,
                    ScanRun.started_at,
                    ScanRun.metadata_json,
                )
                .where(or_(ScanRun.id.like("manual-%"), ScanRun.id.like("scheduled-%")))
                .where(ScanRun.status.in_(["queued", "running", "ingesting"]))
                .where(func.lower(ScanRun.metadata_json["org_label"].astext).in_(list(orgs)))
                .order_by(ScanRun.id)
            )
            runs = []
            for run_id, status, progress, started_at, meta in result.fetchall():
                meta = meta or {}
                runs.append({
                    "runId": run_id,
                    "status": status,
                    "progress": progress or None,
                    "startedAt": started_at.isoformat() if started_at else None,
                    "createdAt": meta.get("createdAt"),
                    "logTail": (meta.get("logTail") or [])[-8:],
                })

        return JSONResponse({"runs": runs, "runIds": [r["runId"] for r in runs]})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.get("/scans/active")
async def get_all_active_scan_runs(
    request: Request,
    _: None = Depends(Permission(VIEW_SOURCES)),
) -> JSONResponse:
    """In-flight source scans (manual or scheduled) across all connections.

    Lets the global progress banner discover scans the user didn't start from
    the current page — notably scheduled runs — by grouping active runs back to
    their connection via the run's org_label. Returns one entry per connection
    that has active runs.
    """
    from sqlalchemy import or_, select
    from src.db.engine import get_session
    from src.db.models import ScanRun

    try:
        # org_label (lower-cased) -> the connections that scan that org.
        conns_by_org: dict[str, list[dict[str, str]]] = {}
        for conn in sources_store.list_connections():
            display = ((conn.get("auth") or {}).get("orgOrOwner") or "").strip()
            for o in _connection_orgs(conn):
                conns_by_org.setdefault(o, []).append(
                    {"connectionId": conn["id"], "org": display or o}
                )
        if not conns_by_org:
            return JSONResponse({"scans": []})

        async with get_session() as session:
            result = await session.execute(
                select(ScanRun.id, ScanRun.metadata_json["org_label"].astext)
                .where(or_(ScanRun.id.like("manual-%"), ScanRun.id.like("scheduled-%")))
                .where(ScanRun.status.in_(["queued", "running", "ingesting"]))
                .order_by(ScanRun.id)
            )
            run_ids_by_org: dict[str, list[str]] = {}
            for run_id, org_label in result.fetchall():
                if org_label:
                    run_ids_by_org.setdefault(org_label.lower(), []).append(run_id)

        scans = []
        for org_lower, conns in conns_by_org.items():
            run_ids = run_ids_by_org.get(org_lower)
            if not run_ids:
                continue
            # If two connections share an org label, attribute the runs to the
            # first — the banner only needs one connection to drive cancel/poll.
            scans.append({**conns[0], "runIds": run_ids})

        return JSONResponse({"scans": scans})
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.post("/connections/{connection_id}/scan/cancel")
@audited(action="source_connection.scan_cancelled", resource_type="source_connection",
         resource_id_param="connection_id")
async def post_cancel_scan_connection(
    connection_id: str,
    body: CancelScanRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    """Cancel queued/active runner jobs for the given manual scan run IDs."""
    from sqlalchemy import update as sa_update
    from src.db.engine import get_session
    from src.db.models import ScanRun
    from src.runner.jobs import list_jobs, update_job_status
    from src.shared.paths import now_iso

    try:
        # Confirm the connection exists before cancelling anything.
        sources_store.get_connection(connection_id)

        if not body.run_ids:
            return JSONResponse({"cancelled": []})

        run_ids_set = set(body.run_ids)

        # Mark ScanRun rows as cancelled.
        async with get_session() as session:
            await session.execute(
                sa_update(ScanRun)
                .where(ScanRun.id.in_(body.run_ids))
                .where(ScanRun.status.in_(["queued", "running", "ingesting"]))
                .values(status="cancelled", finished_at=datetime.now(timezone.utc))
            )
            await session.commit()

        # Signal the runner to stop via job cancellation.
        for job in list_jobs():
            if job.get("status") not in ("queued", "assigned", "running"):
                continue
            if job.get("runId") not in run_ids_set:
                continue
            update_job_status(job["id"], "cancelled", completedAt=now_iso())

        return JSONResponse({"cancelled": body.run_ids})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@source_connections_router.post("/connections/{connection_id}/sync")
@audited(action="source_connection.synced", resource_type="source_connection",
         resource_id_param="connection_id")
async def post_sync_connection(
    connection_id: str,
    request: Request,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> JSONResponse:
    from src.sources.triggers import run_source_sync

    try:
        updated, result = await run_source_sync(connection_id)
        return JSONResponse({"connection": updated, "result": result.to_dict()})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)

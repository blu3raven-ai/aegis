from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.settings import sources_store
from src.settings.sources_store import (
    SourceNotFoundError,
    SourceValidationError,
    SourceStoreError,
)
from src.settings.sources_test_connection import test_connection
from src.settings.router import require_permission
from src.shared.event_bus import Event, get_event_bus

sources_router = APIRouter(prefix="/api/v1/settings", tags=["sources"])

_SCHEDULE_HOURS = {"1h": 1, "3h": 3, "6h": 6, "12h": 12, "24h": 24}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CreateConnectionRequest(BaseModel):
    category: str
    sourceType: str
    name: str
    auth: dict
    scanScope: str = "all"
    excludedItems: list[str] = []
    syncSchedule: str = "6h"


class UpdateConnectionRequest(BaseModel):
    auth: dict | None = None
    scanScope: str | None = None
    excludedItems: list[str] | None = None
    syncSchedule: str | None = None


class TestNewConnectionRequest(BaseModel):
    sourceType: str
    auth: dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_error(error: Any, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": str(error)}, status_code=status_code)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _next_sync_iso(schedule: str) -> str:
    hours = _SCHEDULE_HOURS.get(schedule, 6)
    dt = datetime.now(timezone.utc) + timedelta(hours=hours)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@sources_router.get("/sources")
def get_sources(request: Request, category: str | None = None) -> JSONResponse:
    require_permission(request, "view_sources")
    try:
        connections = sources_store.list_connections(category=category)
        return JSONResponse({"connections": connections})
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@sources_router.get("/sources/internal-orgs")
def get_internal_orgs() -> JSONResponse:
    """Internal endpoint for SSR — returns org metadata without auth.
    Only exposes orgOrOwner, category, and status (no tokens)."""
    try:
        connections = sources_store.list_connections()
        safe = [
            {
                "auth": {"orgOrOwner": c.get("auth", {}).get("orgOrOwner", "")},
                "category": c.get("category", ""),
                "sourceType": c.get("sourceType", ""),
                "status": c.get("status", ""),
            }
            for c in connections
        ]
        return JSONResponse({"connections": safe})
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@sources_router.get("/sources/counts")
def get_source_counts(request: Request) -> JSONResponse:
    require_permission(request, "view_sources")
    try:
        counts = sources_store.count_by_category()
        return JSONResponse({"counts": counts})
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@sources_router.post("/sources/test-new")
async def post_test_new_connection(body: TestNewConnectionRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_sources")
    try:
        result = await test_connection(body.sourceType, body.auth)
        return JSONResponse(result.to_dict())
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@sources_router.post("/sources", status_code=201)
def post_source(body: CreateConnectionRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_sources")
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


@sources_router.get("/sources/{connection_id}")
def get_source(connection_id: str, request: Request) -> JSONResponse:
    require_permission(request, "view_sources")
    try:
        connection = sources_store.get_connection(connection_id)
        return JSONResponse({"connection": connection})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@sources_router.put("/sources/{connection_id}")
def put_source(connection_id: str, body: UpdateConnectionRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_sources")
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


@sources_router.delete("/sources/{connection_id}")
def delete_source(connection_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_sources")
    try:
        sources_store.delete_connection(connection_id)
        return JSONResponse({"ok": True})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@sources_router.post("/sources/{connection_id}/test")
async def post_test_connection(connection_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_sources")
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
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)


@sources_router.post("/sources/{connection_id}/sync")
async def post_sync_connection(connection_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_sources")
    try:
        connection = sources_store.get_connection_with_secrets(connection_id)

        # Set status to syncing
        sources_store.update_connection_status(connection_id, status="syncing")

        # Run the connection test
        result = await test_connection(connection["sourceType"], connection["auth"])

        now = _now_iso()
        next_sync = _next_sync_iso(connection.get("syncSchedule", "6h"))

        if result.success:
            updated = sources_store.update_connection_status(
                connection_id,
                status="connected",
                status_message=result.message,
                discovered_item_count=result.discovered_count,
                discovered_items=result.discovered_items,
                last_synced_at=now,
                next_sync_at=next_sync,
            )
        else:
            updated = sources_store.update_connection_status(
                connection_id,
                status="disconnected",
                status_message=result.message,
                last_synced_at=now,
                next_sync_at=next_sync,
            )

        # Publish SSE event
        get_event_bus().publish_sync(Event(
            event_type="source.synced",
            data={
                "connectionId": connection_id,
                "status": "connected" if result.success else "disconnected",
                "discoveredCount": result.discovered_count,
                "message": result.message,
            },
            require_admin=True,
        ))

        # Emit notification
        from src.notifications.emitter import notify_source_synced
        conn_name = connection.get("name") or connection.get("sourceType", "Unknown")
        notify_source_synced(
            connection_id=connection_id,
            connection_name=conn_name,
            success=result.success,
            message=result.message,
            discovered_count=result.discovered_count,
        )

        return JSONResponse({"connection": updated, "result": result.to_dict()})
    except SourceNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except SourceValidationError as exc:
        return _json_error(exc, status_code=400)
    except SourceStoreError as exc:
        return _json_error(exc, status_code=500)

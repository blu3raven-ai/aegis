"""Activity feed REST router — Phase 52.

GET /api/v1/activity       — paginated unified event timeline
GET /api/v1/activity/types — list of supported event type strings
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request

from src.activity.service import ActivityService, SUPPORTED_TYPES

router = APIRouter(prefix="/api/v1/activity", tags=["activity"])

_service = ActivityService()


@router.get("/types")
def list_activity_types() -> dict[str, Any]:
    """Return the list of event type strings the UI filter dropdown should show."""
    return {"types": SUPPORTED_TYPES}


@router.get("")
def list_activity(
    request: Request,
    types: str | None = None,
    repo_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Return paginated activity events for the requesting user's org.

    types: comma-separated list of event type strings to include.
    cursor: opaque pagination token from the previous response's next_cursor.
    """
    org_id: str | None = getattr(request.state, "user_org", None)
    if not org_id:
        # Fall back to query param for contexts where org_id is forwarded explicitly.
        org_id = request.query_params.get("org_id") or "default"

    parsed_types: list[str] | None = None
    if types:
        parsed_types = [t.strip() for t in types.split(",") if t.strip()]
        if not parsed_types:
            parsed_types = None

    events, next_cursor = _service.list_recent(
        org_id,
        types=parsed_types,
        repo_id=repo_id,
        since=since,
        until=until,
        limit=limit,
        cursor=cursor,
    )

    return {
        "events": [
            {
                "id": e.id,
                "type": e.type,
                "occurred_at": e.occurred_at.isoformat(),
                "actor": e.actor,
                "repo_id": e.repo_id,
                "summary": e.summary,
                "payload": e.payload,
            }
            for e in events
        ],
        "next_cursor": next_cursor,
    }

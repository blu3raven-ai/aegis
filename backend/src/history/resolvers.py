"""GraphQL resolvers for the unified history timeline.

Historic timeline view; the live counterpart is the SSE stream at
/api/v1/history/events/stream. Scoping is fail-closed: viewers with no
team grants get an empty page rather than org-wide rows.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

import strawberry

from src.history.service import HistoryService, SUPPORTED_TYPES


_service = HistoryService()


@strawberry.type
class HistoryEventNode:
    id: str
    type: str
    occurred_at: str
    actor: Optional[str]
    repo_id: Optional[str]
    summary: str
    # JSON-encoded string — payload shape varies per event type and includes
    # nested ints/strings/bools. Encoding once at the resolver boundary keeps
    # the GraphQL contract stable while preserving the full payload.
    payload_json: str


@strawberry.type
class HistoryConnection:
    events: list[HistoryEventNode]
    next_cursor: Optional[str]


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _payload_to_json(payload: dict[str, Any]) -> str:
    try:
        return json.dumps(payload, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return "{}"


def history(
    *,
    types: Optional[list[str]] = None,
    repo_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
    info_context: dict,
) -> HistoryConnection:
    asset_ids = info_context.get("asset_ids") or []
    events, next_cursor = _service.list_recent(
        asset_ids=asset_ids,
        types=types or None,
        repo_id=repo_id,
        since=_parse_iso(since),
        until=_parse_iso(until),
        limit=limit,
        cursor=cursor,
    )
    return HistoryConnection(
        events=[
            HistoryEventNode(
                id=e.id,
                type=e.type,
                occurred_at=e.occurred_at.isoformat() if e.occurred_at else "",
                actor=e.actor,
                repo_id=e.repo_id,
                summary=e.summary,
                payload_json=_payload_to_json(e.payload),
            )
            for e in events
        ],
        next_cursor=next_cursor,
    )


def history_types() -> list[str]:
    return list(SUPPORTED_TYPES)

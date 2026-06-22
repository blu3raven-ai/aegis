"""REST endpoint for the audit log surface.

Replaces the previous GraphQL field ``audit.events``. The audit log is a
single-table read with stable, fixed-shape filters — the kind of read that
belongs on REST per the API decision rules. The wire shape is snake_case end
to end so the frontend no longer needs the camelCase ↔ snake_case adapter.

The contract correction the previous GQL migration shipped is preserved:
``actor_user_id`` is published as ``actor_id`` and ``metadata_json`` as
``metadata``.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.db.engine import get_session
from src.db.models import AuditEvent

router = APIRouter(prefix="/api/v1/settings/audit", tags=["settings"])

MAX_LIMIT = 500


def _parse_iso(value: str, field: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"invalid ISO timestamp for {field}: {value!r}",
        ) from exc


def _row_to_dict(row: AuditEvent) -> dict[str, Any]:
    occurred = row.occurred_at.isoformat() if row.occurred_at is not None else None
    return {
        "id": row.id,
        "action": row.action,
        "actor_id": row.actor_user_id,
        "actor_email": row.actor_email,
        "actor_role": row.actor_role,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "request_method": row.request_method,
        "request_path": row.request_path,
        "request_ip": row.request_ip,
        "user_agent": row.user_agent,
        "changes": row.changes,
        "metadata": row.metadata_json,
        "status_code": row.status_code,
        "occurred_at": occurred,
    }


@router.get("/events")
async def list_audit_events(
    request: Request,
    action: Optional[str] = None,
    actor_id: Optional[str] = Query(default=None, alias="actor_id"),
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict[str, Any]:
    if os.getenv("AEGIS_AUDIT_LOG_ENABLED", "true").lower() == "false":
        raise HTTPException(status_code=409, detail="audit log is disabled")

    clamped_limit = max(1, min(limit, MAX_LIMIT))
    clamped_offset = max(0, offset)

    since_dt = _parse_iso(since, "since") if since else None
    until_dt = _parse_iso(until, "until") if until else None

    def _apply_filters(stmt):
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        if actor_id:
            stmt = stmt.where(AuditEvent.actor_user_id == actor_id)
        if resource_type:
            stmt = stmt.where(AuditEvent.resource_type == resource_type)
        if resource_id:
            stmt = stmt.where(AuditEvent.resource_id == resource_id)
        if since_dt is not None:
            stmt = stmt.where(AuditEvent.occurred_at >= since_dt)
        if until_dt is not None:
            stmt = stmt.where(AuditEvent.occurred_at <= until_dt)
        return stmt

    async with get_session() as session:
        list_stmt = _apply_filters(select(AuditEvent))
        list_stmt = list_stmt.order_by(AuditEvent.occurred_at.desc().nullslast())
        list_stmt = list_stmt.limit(clamped_limit).offset(clamped_offset)
        rows = (await session.execute(list_stmt)).scalars().all()

        count_stmt = _apply_filters(select(func.count()).select_from(AuditEvent))
        total = (await session.execute(count_stmt)).scalar_one()

    return {
        "events": [_row_to_dict(r) for r in rows],
        "total_count": int(total or 0),
        "limit": clamped_limit,
        "offset": clamped_offset,
    }

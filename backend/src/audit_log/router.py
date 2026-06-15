"""REST endpoint for querying the audit log.

Admin-only: requires manage_settings permission.
Returns paginated AuditEvent rows with optional filters.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from src.audit_log.models import AuditEventRecord
from src.db.helpers import run_db
from src.db.models import AuditEvent
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

_MAX_LIMIT = 500


@router.get("/events")
def list_audit_events(
    request: Request,
    action: str | None = None,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Return paginated audit events."""
    require_permission(request, "manage_settings")

    if os.getenv("AEGIS_AUDIT_LOG_ENABLED", "true").lower() == "false":
        raise HTTPException(status_code=403, detail="audit log is disabled")

    limit = max(1, min(limit, _MAX_LIMIT))
    offset = max(0, offset)

    def _query(session):
        stmt = select(AuditEvent)

        if action:
            stmt = stmt.where(AuditEvent.action == action)
        if actor_id:
            stmt = stmt.where(AuditEvent.actor_user_id == actor_id)
        if resource_type:
            stmt = stmt.where(AuditEvent.resource_type == resource_type)
        if resource_id:
            stmt = stmt.where(AuditEvent.resource_id == resource_id)
        if since:
            stmt = stmt.where(AuditEvent.occurred_at >= since)
        if until:
            stmt = stmt.where(AuditEvent.occurred_at <= until)

        stmt = stmt.order_by(AuditEvent.occurred_at.desc().nullslast())
        stmt = stmt.limit(limit).offset(offset)
        return session.execute(stmt)

    import asyncio

    async def _async_query(session):
        result = await _query(session)
        return result.scalars().all()

    rows = run_db(_async_query)
    return {
        "events": [AuditEventRecord.model_validate(r).model_dump() for r in rows],
        "limit": limit,
        "offset": offset,
    }

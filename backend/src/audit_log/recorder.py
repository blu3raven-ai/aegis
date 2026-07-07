"""AuditRecorder — writes structured audit events to the database."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.db.helpers import run_db
from src.db.models import AuditEvent

logger = logging.getLogger(__name__)


def client_ip_from_request(request: Any) -> str | None:
    """Client IP for an audit record, honouring X-Forwarded-For.

    Returns the first hop of X-Forwarded-For when present (the original client
    behind a trusted reverse proxy), otherwise the direct peer address."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@dataclass
class ActorInfo:
    user_id: str | None = None
    username: str | None = None
    email: str | None = None
    role: str | None = None


@dataclass
class RequestContext:
    method: str | None = None
    path: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    status_code: int | None = None


class AuditRecorder:
    """Thread-safe recorder that persists an AuditEvent row per call.

    Swallowing errors deliberately — a failed audit write must never break
    the primary request path. Errors are logged at WARNING level instead.
    """

    def _build_event(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None,
        actor: ActorInfo | None,
        changes: dict[str, Any] | None,
        metadata: dict[str, Any] | None,
        request: RequestContext | None,
        org_id: str = "default",
    ) -> AuditEvent | None:
        """Construct the AuditEvent row, or None when audit logging is disabled.

        Shared by `record()` (top-level, own run_db) and `record_in_session()`
        (nested inside an existing session) so both build the row identically.
        """
        if os.getenv("AEGIS_AUDIT_LOG_ENABLED", "true").lower() == "false":
            return None

        actor = actor or ActorInfo()
        request = request or RequestContext()
        now = datetime.now(timezone.utc)
        return AuditEvent(
            action=action,
            actor_user_id=actor.user_id,
            actor_username=actor.username,
            actor_email=actor.email,
            actor_role=actor.role,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            request_method=request.method,
            request_path=request.path,
            request_ip=request.ip,
            user_agent=request.user_agent,
            changes=changes,
            metadata_json=metadata,
            status_code=request.status_code,
            created_at=now,
            occurred_at=now,
            org_id=org_id,
        )

    def record(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        actor: ActorInfo | None = None,
        changes: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        request: RequestContext | None = None,
        org_id: str = "default",
    ) -> None:
        event = self._build_event(
            action=action, resource_type=resource_type, resource_id=resource_id,
            actor=actor, changes=changes, metadata=metadata, request=request,
            org_id=org_id,
        )
        if event is None:
            return

        async def _write(session):
            session.add(event)

        try:
            run_db(_write)
        except Exception:
            logger.warning("audit_log: failed to persist audit event action=%s", action, exc_info=True)

    def record_in_session(
        self,
        session: Any,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        actor: ActorInfo | None = None,
        changes: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        request: RequestContext | None = None,
        org_id: str = "default",
    ) -> None:
        """Add an audit event to an existing AsyncSession.

        For callers already running inside a `run_db()` coroutine, where
        `record()` would deadlock by nesting another `run_db()`. The event is
        added to the caller's session and committed with the caller's
        transaction — so unlike `record()`, a failure here is NOT swallowed
        (it belongs to the surrounding unit of work).
        """
        event = self._build_event(
            action=action, resource_type=resource_type, resource_id=resource_id,
            actor=actor, changes=changes, metadata=metadata, request=request,
            org_id=org_id,
        )
        if event is not None:
            session.add(event)


_recorder = AuditRecorder()


def get_recorder() -> AuditRecorder:
    return _recorder

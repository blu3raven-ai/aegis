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
    ) -> None:
        if os.getenv("AEGIS_AUDIT_LOG_ENABLED", "true").lower() == "false":
            return

        actor = actor or ActorInfo()
        request = request or RequestContext()
        now = datetime.now(timezone.utc)

        async def _write(session):
            session.add(AuditEvent(
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
            ))

        try:
            run_db(_write)
        except Exception:
            logger.warning("audit_log: failed to persist audit event action=%s", action, exc_info=True)


_recorder = AuditRecorder()


def get_recorder() -> AuditRecorder:
    return _recorder

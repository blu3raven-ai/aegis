from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.db.helpers import run_db
from src.db.models import AuditEvent


def record_event(
    *,
    action: str,
    actor_user_id: str | None = None,
    actor_username: str | None = None,
    target: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Records an audit event to the database."""
    async def _query(session):
        session.add(AuditEvent(
            action=action,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            target=target,
            metadata_json=metadata or {},
            created_at=datetime.now(timezone.utc),
        ))

    run_db(_query)

"""Pydantic schema for audit log read/query operations."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AuditEventRecord(BaseModel):
    """Read-only view of an audit_events row returned by the query API."""

    model_config = {"from_attributes": True}

    id: int
    action: str
    actor_user_id: str | None = None
    actor_username: str | None = None
    actor_email: str | None = None
    actor_role: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    target: str | None = None
    request_method: str | None = None
    request_path: str | None = None
    request_ip: str | None = None
    user_agent: str | None = None
    changes: dict[str, Any] | None = None
    metadata_json: dict[str, Any] | None = None
    status_code: int | None = None
    occurred_at: datetime | None = None
    created_at: datetime

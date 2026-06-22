from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.notifications.store import (
    mark_as_read,
    delete_notification,
)

router = APIRouter(prefix="/api/v1/notifications/inbox", tags=["notifications"])


class MarkReadRequest(BaseModel):
    notification_id: str | None = None  # None = mark all


@router.post("/mark-read")
async def mark_read(body: MarkReadRequest, request: Request):
    user_id = request.state.user_sub
    count = mark_as_read(user_id, body.notification_id)
    return {"ok": True, "marked": count}


@router.delete("/{notification_id}")
async def remove_notification(notification_id: str, request: Request):
    user_id = request.state.user_sub
    deleted = delete_notification(user_id, notification_id)
    return {"ok": deleted}

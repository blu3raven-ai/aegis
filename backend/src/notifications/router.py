from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.notifications.store import (
    get_notifications,
    get_unread_count,
    mark_as_read,
    delete_notification,
)

router = APIRouter(prefix="/notifications/api", tags=["notifications"])


@router.get("/list")
async def list_notifications(
    request: Request,
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
):
    user_id = request.state.user_sub
    notifications, total = get_notifications(
        user_id, unread_only=unread_only, limit=limit, offset=offset
    )
    return {"notifications": notifications, "total": total}


@router.get("/unread-count")
async def unread_count(request: Request):
    user_id = request.state.user_sub
    count = get_unread_count(user_id)
    return {"count": count}


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

"""REST endpoints for managing outbound notification destinations."""
from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.notifications.destination import (
    VALID_DEST_TYPES,
    create_destination,
    delete_destination,
    get_destination,
    list_deliveries_for_destination,
    list_destinations,
    update_destination,
)
from src.notifications.test_send import build_test_payload, send_test_payload
from src.audit_log.decorators import audited
from src.settings.router import require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications-admin"])


class CreateDestinationRequest(BaseModel):
    destination_type: str
    name: str
    config: dict[str, Any]
    enabled: bool = True
    event_filter: dict[str, Any] | None = None


class UpdateDestinationRequest(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    event_filter: dict[str, Any] | None = None


@router.get("/destinations")
def list_notification_destinations(request: Request) -> dict:
    require_permission(request, "manage_settings")
    return {"destinations": list_destinations()}


@router.get("/destinations/{dest_id}")
def get_notification_destination(request: Request, dest_id: int) -> dict:
    require_permission(request, "manage_settings")
    dest = get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")
    return dest


@audited(action="notification.destination.created", resource_type="notification_destination")
@router.post("/destinations", status_code=201)
def create_notification_destination(
    request: Request, body: CreateDestinationRequest
) -> dict:
    require_permission(request, "manage_settings")

    if body.destination_type not in VALID_DEST_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"destination_type must be one of {sorted(VALID_DEST_TYPES)}",
        )

    try:
        dest = create_destination(
            destination_type=body.destination_type,
            name=body.name,
            config=body.config,
            enabled=body.enabled,
            event_filter=body.event_filter,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        if "uq_notif_dest_name" in str(exc):
            raise HTTPException(
                status_code=409, detail="a destination with that name already exists"
            ) from exc
        logger.exception("create_destination failed")
        raise HTTPException(status_code=500, detail="internal error") from exc

    return dest


@audited(action="notification.destination.updated", resource_type="notification_destination", resource_id_param="dest_id")
@router.put("/destinations/{dest_id}")
def update_notification_destination(
    request: Request, dest_id: int, body: UpdateDestinationRequest
) -> dict:
    require_permission(request, "manage_settings")

    dest = update_destination(
        dest_id,
        name=body.name,
        config=body.config,
        enabled=body.enabled,
        event_filter=body.event_filter,
    )
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")
    return dest


@audited(action="notification.destination.deleted", resource_type="notification_destination", resource_id_param="dest_id")
@router.delete("/destinations/{dest_id}", status_code=204)
def delete_notification_destination(request: Request, dest_id: int) -> None:
    require_permission(request, "manage_settings")

    deleted = delete_destination(dest_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="destination not found")


@router.get("/destinations/{dest_id}/deliveries")
def list_destination_deliveries(
    request: Request,
    dest_id: int,
    limit: int = 50,
) -> dict:
    require_permission(request, "manage_settings")

    dest = get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")

    return {"deliveries": list_deliveries_for_destination(dest_id, limit=min(limit, 200))}


@audited(
    action="notification.destination.test_sent",
    resource_type="notification_destination",
    resource_id_param="dest_id",
)
@router.post("/destinations/{dest_id}/test")
def test_send_destination(request: Request, dest_id: int) -> dict:
    """Send a canned test payload through the destination's channel."""
    require_permission(request, "manage_settings")

    dest = get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")

    dtype = dest.get("destination_type", "")
    if dtype not in VALID_DEST_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"unsupported destination channel: {dtype}",
        )
    payload = build_test_payload(dtype, dest.get("name", ""))

    start = time.monotonic()
    result = send_test_payload(dtype, payload, dest.get("config") or {})
    latency_ms = int((time.monotonic() - start) * 1000)

    if result.success:
        return {
            "status": "delivered",
            "channel": dtype,
            "latency_ms": latency_ms,
        }
    return {
        "status": "failed",
        "channel": dtype,
        "error": result.error or "delivery failed",
        "latency_ms": latency_ms,
    }

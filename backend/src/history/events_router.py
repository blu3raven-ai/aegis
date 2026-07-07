"""SSE streaming endpoint — unified real-time event delivery."""
from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse, JSONResponse

from src.shared.event_bus import get_event_bus
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import VIEW_DASHBOARDS

logger = logging.getLogger(__name__)

events_router = APIRouter(prefix="/api/v1/history/events", tags=["history"])

HEARTBEAT_INTERVAL = 30  # seconds


async def _resolve_allowed_asset_ids(request: Request, role: str) -> "frozenset[str] | None":
    """Return the asset IDs this caller may see in asset-scoped SSE events.

    Admins and owners receive None (no filter — see all asset events).
    Other roles receive the frozenset of their granted asset IDs.
    An empty frozenset means no grants — no asset-scoped events delivered.
    """
    if role in ("admin", "owner"):
        return None
    from src.authz.enforcement.scope import get_user_asset_ids
    from src.db.engine import async_session_factory
    ctx = {
        "user_id": getattr(request.state, "user_sub", None),
        "role": role,
    }
    async with async_session_factory() as db:
        asset_ids = await get_user_asset_ids(db, ctx)
    return frozenset(asset_ids)


@events_router.get("/stream")
async def sse_stream(
    request: Request,
    _: None = Depends(Permission(VIEW_DASHBOARDS)),
) -> StreamingResponse:
    user_sub = getattr(request.state, "user_sub", None)
    if not user_sub:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    role = getattr(request.state, "user_role", None) or "viewer"
    allowed_asset_ids = await _resolve_allowed_asset_ids(request, role)

    bus = get_event_bus()

    try:
        _sub_obj, subscription = bus.subscribe(
            user_id=user_sub, role=role, allowed_asset_ids=allowed_asset_ids
        )
    except ConnectionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=429)

    async def generate_with_heartbeat():
        event_iter = subscription.__aiter__()
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(
                    event_iter.__anext__(), timeout=HEARTBEAT_INTERVAL
                )
                event_id = bus.next_event_id()
                yield event.to_sse(event_id)
            except asyncio.TimeoutError:
                yield f":heartbeat {int(time.time())}\n\n"
            except StopAsyncIteration:
                break
            except asyncio.CancelledError:
                break

    return StreamingResponse(
        generate_with_heartbeat(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

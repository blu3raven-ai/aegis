"""SSE streaming endpoint — unified real-time event delivery."""
from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse, JSONResponse

from src.shared.event_bus import get_event_bus
from src.settings.router import require_permission

logger = logging.getLogger(__name__)

events_router = APIRouter(prefix="/api/v1/events", tags=["events"])

HEARTBEAT_INTERVAL = 30  # seconds


@events_router.get("/stream")
async def sse_stream(request: Request) -> StreamingResponse:
    user_sub = getattr(request.state, "user_sub", None)
    if not user_sub:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    require_permission(request, "view_dashboards")

    role = getattr(request.state, "user_role", None) or "viewer"

    bus = get_event_bus()

    try:
        _sub_obj, subscription = bus.subscribe(user_id=user_sub, role=role)
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

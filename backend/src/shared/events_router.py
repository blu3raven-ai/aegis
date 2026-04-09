"""SSE streaming endpoint — unified real-time event delivery."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse, JSONResponse

from src.shared.event_bus import get_event_bus
from src.settings.router import require_permission

logger = logging.getLogger(__name__)

events_router = APIRouter(prefix="/events/api", tags=["events"])

HEARTBEAT_INTERVAL = 30  # seconds


def _get_user_context(request: Request) -> dict[str, Any] | None:
    """Extract user identity from JWT middleware state."""
    user_sub = getattr(request.state, "user_sub", None)
    if not user_sub:
        return None
    role = getattr(request.state, "user_role", None) or "viewer"
    # For SSE, user sees events for ALL orgs they have source connections for
    from src.shared.config import get_orgs_from_source_connections
    orgs = get_orgs_from_source_connections()
    return {"user_id": user_sub, "role": role, "orgs": orgs}


@events_router.get("/stream")
async def sse_stream(request: Request) -> StreamingResponse:
    ctx = _get_user_context(request)
    if not ctx:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    require_permission(request, "view_dashboards")

    bus = get_event_bus()

    try:
        subscription = bus.subscribe(
            user_id=ctx["user_id"],
            role=ctx["role"],
            orgs=ctx["orgs"],
        )
    except ConnectionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=429)

    async def generate_with_heartbeat():
        last_heartbeat = time.time()
        last_org_refresh = time.time()
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
                last_heartbeat = time.time()
            except asyncio.TimeoutError:
                yield f":heartbeat {int(time.time())}\n\n"
                last_heartbeat = time.time()
            except StopAsyncIteration:
                break
            except asyncio.CancelledError:
                break

            # Periodically re-resolve the user's org scope so that
            # newly added/removed source connections take effect
            # without requiring a reconnect.
            if time.time() - last_org_refresh >= 60:
                from src.shared.config import get_orgs_from_source_connections
                refreshed_orgs = get_orgs_from_source_connections()
                if refreshed_orgs != subscription.orgs:
                    subscription.orgs = refreshed_orgs
                    logger.debug("SSE org scope refreshed for user %s", ctx["user_id"])
                last_org_refresh = time.time()

    return StreamingResponse(
        generate_with_heartbeat(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

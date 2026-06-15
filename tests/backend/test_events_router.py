import asyncio

import pytest
from httpx import AsyncClient, ASGITransport
from src.main import app
from src.shared.event_bus import Event, get_event_bus


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sse_stream_requires_auth():
    transport = ASGITransport(app=app)
    # Use "http://testserver" so TrustedHostMiddleware accepts the Host header.
    # Without a session cookie the SessionAuthMiddleware returns 401.
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/api/v1/events/stream")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sse_stream_receives_event(monkeypatch):
    """Test the SSE endpoint function directly, bypassing Starlette middleware.

    Starlette's BaseHTTPMiddleware buffers the entire StreamingResponse body
    before forwarding, which breaks SSE in the ASGI test transport. We
    therefore call the route handler directly with a mock Request and iterate
    the streaming body ourselves — this is the correct approach for SSE tests.
    """
    from unittest.mock import MagicMock
    import src.shared.events_router as er
    from src.shared.events_router import sse_stream

    bus = get_event_bus()

    # Build a mock Request that looks authenticated
    mock_request = MagicMock()
    mock_request.state.user_sub = "user-sse-1"
    mock_request.state.user_role = "admin"

    # Patch _get_user_context so we don't need real source connections
    monkeypatch.setattr(er, "_get_user_context", lambda req: {
        "user_id": "user-sse-1",
        "role": "admin",
        "orgs": ["test-org"],
    })

    # Patch require_permission so we don't need real role DB lookups
    monkeypatch.setattr(er, "require_permission", lambda req, perm: None)

    # Simulate disconnect after we've read enough data
    disconnect_after = 4  # stop after collecting 4 non-empty lines
    call_count = 0

    async def mock_is_disconnected():
        nonlocal call_count
        call_count += 1
        return False  # never report disconnect; we'll break out of iteration

    mock_request.is_disconnected = mock_is_disconnected

    response = await sse_stream(mock_request)

    assert response.media_type == "text/event-stream"
    assert response.headers.get("Cache-Control") == "no-cache, no-transform"
    assert response.headers.get("X-Accel-Buffering") == "no"

    chunks: list[str] = []

    async def collect():
        gen = response.body_iterator
        async for chunk in gen:
            chunks.append(chunk if isinstance(chunk, str) else chunk.decode())
            # Stop once we have the scan.progress event
            joined = "".join(chunks)
            if "scan.progress" in joined and '"percent":42' in joined:
                break

    # Publish the event slightly after the generator starts
    async def publish_after_delay():
        await asyncio.sleep(0.1)
        bus.publish(Event(
            event_type="scan.progress",
            data={"tool": "dependencies", "org": "test-org", "percent": 42},
            org="test-org",
        ))

    await asyncio.wait_for(
        asyncio.gather(collect(), publish_after_delay()),
        timeout=3.0,
    )

    joined = "".join(chunks)
    assert "event:scan.progress" in joined
    assert '"percent":42' in joined

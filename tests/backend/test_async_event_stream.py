"""Tests for AsyncEventStream — asyncio-compatible mirror of EventStream."""
from __future__ import annotations

import pytest
import pytest_asyncio
from testcontainers.redis import RedisContainer

from src.shared.async_event_stream import AsyncEventStream
from src.shared.event_types.code import CodePushEvent


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


@pytest_asyncio.fixture
async def stream(redis_container):
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    url = f"redis://{host}:{port}"
    s = AsyncEventStream({"url": url, "stream_prefix": "async-test.events.", "max_len": 100})
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_async_publish_writes_to_stream(stream):
    event = CodePushEvent(
        org_id="acme-org",
        payload={"repo_id": "r-1", "after_sha": "a" * 40},
    )
    stream_id = await stream.publish(event)
    assert stream_id is not None
    # Verify entry exists
    entries = await stream._client.xrange("async-test.events.code.push", count=10)
    assert len(entries) >= 1


@pytest.mark.asyncio
async def test_async_publish_handles_datetime_payload(stream):
    """Same fix as sync EventStream — non-JSON-safe values should not crash."""
    import datetime
    event = CodePushEvent(
        org_id="acme-org",
        payload={
            "repo_id": "r-dt",
            "pushed_at": datetime.datetime(2026, 5, 31, 12, 0, tzinfo=datetime.timezone.utc),
        },
    )
    stream_id = await stream.publish(event)
    assert stream_id is not None

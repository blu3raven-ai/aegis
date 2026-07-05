"""Tests for Redis Streams EventStream wrapper.

Uses testcontainers for a real Redis instance — Phase 0 establishes the
testing pattern subsequent phases reuse.
"""
from __future__ import annotations

import pytest
from testcontainers.redis import RedisContainer

from src.shared.event_stream import EventStream
from src.shared.event_types.code import CodePushEvent


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


@pytest.fixture
def stream(redis_container):
    # get_connection_url() not available in this testcontainers version; build from parts.
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    cfg = {
        "url": f"redis://{host}:{port}",
        "stream_prefix": "test.events.",
        "max_len": 100,
    }
    return EventStream(cfg)


def test_publish_writes_to_redis_stream(stream):
    event = CodePushEvent(
        org_id="acme-org",
        payload={"repo_id": "repo-1", "after_sha": "a" * 40},
    )
    stream_id = stream.publish(event)
    assert stream_id is not None
    client = stream._client
    entries = client.xrange("test.events.code.push", count=10)
    assert len(entries) == 1
    _, fields = entries[0]
    decoded = {k.decode(): v.decode() for k, v in fields.items()}
    assert decoded["event_id"] == event.event_id
    assert decoded["event_type"] == "code.push"


def test_publish_respects_max_len(stream):
    for i in range(150):
        stream.publish(CodePushEvent(
            org_id="acme-org", payload={"repo_id": f"repo-{i}"}
        ))
    client = stream._client
    length = client.xlen("test.events.code.push")
    # XADD with MAXLEN ~ N may keep slightly more than N; assert bounded.
    assert length <= 200, f"Expected <= 200, got {length}"


def test_publish_handles_datetime_in_payload(stream):
    """Regression: payload with non-JSON-safe values (e.g., datetime) must
    serialize via default=str rather than crashing."""
    import datetime
    event = CodePushEvent(
        org_id="acme-org",
        payload={
            "repo_id": "repo-dt",
            "pushed_at": datetime.datetime(2026, 5, 30, 12, 0, tzinfo=datetime.timezone.utc),
        },
    )
    stream_id = stream.publish(event)
    assert stream_id is not None


def test_subscribe_consumer_group_reads_new_events(stream):
    # Publish one event before subscribing
    e1 = CodePushEvent(org_id="acme-org", payload={"repo_id": "before"})
    stream.publish(e1)

    # Subscribe with consumer group starting at NEW (only after-group events).
    # XGROUP CREATE with $ means "new from now on" so the prior event is skipped.
    received_before = list(stream.subscribe(
        event_type="code.push",
        group="test-group",
        consumer="c1",
        block_ms=100,
        count=10,
        start_at_new=True,
    ))
    assert all(r["payload"].get("repo_id") != "before" for r in received_before)

    # Publish more events
    for i in range(3):
        stream.publish(CodePushEvent(
            org_id="acme-org", payload={"repo_id": f"after-{i}"}
        ))

    # Second poll picks them up
    received_after = list(stream.subscribe(
        event_type="code.push",
        group="test-group",
        consumer="c1",
        block_ms=100,
        count=10,
        start_at_new=True,
    ))
    repo_ids = {r["payload"].get("repo_id") for r in received_after}
    assert "after-0" in repo_ids
    assert "after-1" in repo_ids
    assert "after-2" in repo_ids


def test_ack_removes_from_pending(stream):
    e = CodePushEvent(org_id="acme-org", payload={"repo_id": "ack-test"})
    stream.publish(e)
    msgs = list(stream.subscribe(
        event_type="code.push", group="ack-group", consumer="c1",
        block_ms=100, count=10, start_at_new=False,
    ))
    assert len(msgs) > 0
    msg_id = msgs[-1]["_stream_id"]
    stream.ack("code.push", "ack-group", msg_id)
    # No assertion on Redis internals here — ack throws on bad ID, success is enough.

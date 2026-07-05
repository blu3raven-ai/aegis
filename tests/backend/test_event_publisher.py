"""Tests for the unified event publisher.

The publisher routes events to the durable Redis stream and bridges
relevant ones to the existing in-memory SSE EventBus for live UI updates.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.shared.event_publisher import EventPublisher
from src.shared.event_types.code import CodePushEvent


def test_publisher_writes_to_durable_stream():
    durable = MagicMock()
    sse_bus = MagicMock()
    publisher = EventPublisher(durable, sse_bus)
    event = CodePushEvent(org_id="acme-org", payload={"repo_id": "r-1"})
    publisher.publish(event)
    durable.publish.assert_called_once_with(event)


def test_publisher_bridges_relevant_events_to_sse():
    durable = MagicMock()
    sse_bus = MagicMock()
    publisher = EventPublisher(durable, sse_bus)
    event = CodePushEvent(org_id="acme-org", payload={"repo_id": "r-1"})
    publisher.publish(event)
    # Code events bridge to SSE for "scan triggered" UI updates
    sse_bus.publish_sync.assert_called_once()
    args, _ = sse_bus.publish_sync.call_args
    sse_event = args[0]
    assert sse_event.event_type == "code.push"
    assert sse_event.org == "acme-org"


def test_publisher_skips_sse_for_internal_only_events():
    durable = MagicMock()
    sse_bus = MagicMock()
    publisher = EventPublisher(durable, sse_bus)
    from src.shared.event_types.finding import FindingMergedEvent
    event = FindingMergedEvent(
        org_id="acme-org",
        payload={"finding_id": "F-1", "into_finding_id": "F-2"},
    )
    publisher.publish(event)
    durable.publish.assert_called_once()
    sse_bus.publish_sync.assert_not_called()


def test_get_event_publisher_returns_singleton(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    from src.shared.event_publisher import get_event_publisher
    p1 = get_event_publisher()
    p2 = get_event_publisher()
    assert p1 is p2

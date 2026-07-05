"""Regression: ``org_id`` and ``source_component`` must survive the
EventPublisher -> EventBus -> sync-listener round trip.

Before this fix, both fields were dropped at the typed->SseEvent conversion,
leaving listeners unable to tell which provider produced an event.
"""
from __future__ import annotations

import asyncio
import threading

from src.shared.event_bus import Event as SseEvent, EventBus
from src.shared.event_publisher import EventPublisher
from src.shared.event_types.code import CodePushEvent


def test_publisher_propagates_org_id_and_source_component_to_listener():
    bus = EventBus()
    publisher = EventPublisher(sse_bus=bus)
    received: list[SseEvent] = []

    bus.register_listener(received.append)

    publisher.publish(
        CodePushEvent(
            org_id="acme-org",
            source_component="integrations.github",
            payload={"repo_id": "acme-org/payments-api", "after_sha": "deadbeef"},
        )
    )

    assert len(received) == 1
    event = received[0]
    assert event.event_type == "code.push"
    assert event.data["org_id"] == "acme-org"
    assert event.data["source_component"] == "integrations.github"
    assert event.data["payload"]["repo_id"] == "acme-org/payments-api"
    assert event.data["payload"]["after_sha"] == "deadbeef"
    assert event.data["event_id"]


def test_publisher_propagation_through_running_loop():
    """When publish_sync runs on a live loop it schedules via call_soon_threadsafe."""
    received: list[SseEvent] = []
    ready = threading.Event()
    captured_loop: dict = {}

    async def _main() -> None:
        bus = EventBus()
        loop = asyncio.get_running_loop()
        bus.set_loop(loop)
        bus.register_listener(received.append)
        captured_loop["loop"] = loop
        publisher = EventPublisher(sse_bus=bus)

        def _publish_from_other_thread() -> None:
            publisher.publish(
                CodePushEvent(
                    org_id="acme-org",
                    source_component="integrations.gitlab",
                    payload={"repo_id": "acme-org/repo", "after_sha": "abc"},
                )
            )
            ready.set()

        t = threading.Thread(target=_publish_from_other_thread)
        t.start()
        ready.wait(timeout=2.0)
        t.join(timeout=2.0)
        # Yield to the loop so the threadsafe-scheduled publish runs.
        for _ in range(5):
            await asyncio.sleep(0.01)
            if received:
                break

    asyncio.run(_main())

    assert len(received) == 1
    assert received[0].data["org_id"] == "acme-org"
    assert received[0].data["source_component"] == "integrations.gitlab"


def test_existing_consumer_shape_still_works():
    """NotificationEventRouter reads ``event.data.get("event_id", "")`` —
    adding sibling keys must not break that."""
    bus = EventBus()
    publisher = EventPublisher(sse_bus=bus)
    received: list[SseEvent] = []
    bus.register_listener(received.append)

    publisher.publish(
        CodePushEvent(
            org_id="acme",
            source_component="integrations.github",
            payload={"x": 1},
        )
    )

    assert received[0].data.get("event_id", "") != ""
    assert received[0].data.get("payload") == {"x": 1}

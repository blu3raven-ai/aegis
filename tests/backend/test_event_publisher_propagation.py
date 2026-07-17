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


def test_target_user_ids_scopes_sse_delivery():
    """An event with target_user_ids is delivered only to those users — the
    realtime mirror of a scoped notification must not fan out to everyone."""

    async def _run() -> None:
        bus = EventBus()
        _, alice = bus.subscribe("alice", "viewer")
        _, bob = bus.subscribe("bob", "viewer")
        # One event targeted at alice, one at bob — bob must not receive alice's.
        bus.publish(SseEvent(
            event_type="notification.new",
            data={"m": "secret"},
            target_user_ids=frozenset({"alice"}),
        ))
        bus.publish(SseEvent(
            event_type="notification.new",
            data={"m": "for-bob"},
            target_user_ids=frozenset({"bob"}),
        ))

        a = await asyncio.wait_for(alice.__anext__(), 1.0)
        b = await asyncio.wait_for(bob.__anext__(), 1.0)
        # bob skipped alice's event; his first delivered event is his own,
        # proving the targeted filter excluded him from alice's.
        assert a.data["m"] == "secret"
        assert b.data["m"] == "for-bob"

    asyncio.run(_run())


def test_unscoped_event_reaches_admins_only():
    """Fail-closed: an event with no scoping signal is delivered to an admin
    subscriber but not to a non-admin — a new publish path can't broadcast
    scoped data by default."""

    async def _run() -> None:
        bus = EventBus()
        _, viewer = bus.subscribe("v", "viewer")
        _, admin = bus.subscribe("a", "admin")
        bus.publish(SseEvent(event_type="scan.progress", data={"m": "unscoped"}))
        # A follow-up targeted at the viewer is his only deliverable event.
        bus.publish(SseEvent(
            event_type="notification.new",
            data={"m": "for-viewer"},
            target_user_ids=frozenset({"v"}),
        ))

        admin_evt = await asyncio.wait_for(admin.__anext__(), 1.0)
        viewer_evt = await asyncio.wait_for(viewer.__anext__(), 1.0)
        assert admin_evt.data["m"] == "unscoped"       # admin sees the unscoped event
        assert viewer_evt.data["m"] == "for-viewer"    # viewer skipped it entirely

    asyncio.run(_run())


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

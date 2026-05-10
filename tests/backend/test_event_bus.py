# backend/tests/test_event_bus.py
import asyncio
import pytest
from src.shared.event_bus import Event, EventBus


@pytest.mark.asyncio
async def test_subscribe_receives_published_event():
    bus = EventBus()
    received = []

    async def consume():
        async for event in bus.subscribe(user_id="u1", role="admin", orgs=["org-a"]):
            received.append(event)
            break  # just consume one

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)  # let subscriber start

    bus.publish(Event(
        event_type="scan.progress",
        data={"tool": "dependencies", "org": "org-a", "runId": "r1", "progress": {"percent": 50}},
        org="org-a",
        require_admin=False,
    ))

    await asyncio.wait_for(task, timeout=1.0)
    assert len(received) == 1
    assert received[0].event_type == "scan.progress"
    assert received[0].data["progress"]["percent"] == 50


@pytest.mark.asyncio
async def test_org_scope_filtering():
    """User in org-a should NOT receive events for org-b."""
    bus = EventBus()
    received = []

    async def consume():
        async for event in bus.subscribe(user_id="u1", role="viewer", orgs=["org-a"]):
            received.append(event)
            break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)

    # Publish to org-b — should NOT be delivered
    bus.publish(Event(
        event_type="scan.progress",
        data={"tool": "dependencies", "org": "org-b"},
        org="org-b",
        require_admin=False,
    ))
    # Publish to org-a — should be delivered
    bus.publish(Event(
        event_type="scan.progress",
        data={"tool": "dependencies", "org": "org-a"},
        org="org-a",
        require_admin=False,
    ))

    await asyncio.wait_for(task, timeout=1.0)
    assert len(received) == 1
    assert received[0].data["org"] == "org-a"


@pytest.mark.asyncio
async def test_admin_only_event_filtered_for_non_admin():
    """Non-admin users should NOT receive admin-only events."""
    bus = EventBus()
    received = []

    async def consume():
        async for event in bus.subscribe(user_id="u1", role="viewer", orgs=["org-a"]):
            received.append(event)
            break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)

    bus.publish(Event(
        event_type="runner.status",
        data={"runnerId": "r1", "status": "online"},
        org="org-a",
        require_admin=True,
    ))
    # Follow with a non-admin event to unblock the consumer
    bus.publish(Event(
        event_type="scan.progress",
        data={"tool": "dependencies", "org": "org-a"},
        org="org-a",
        require_admin=False,
    ))

    await asyncio.wait_for(task, timeout=1.0)
    assert len(received) == 1
    assert received[0].event_type == "scan.progress"


@pytest.mark.asyncio
async def test_max_connections_per_user():
    """4th connection from same user should be rejected."""
    bus = EventBus()
    tasks = []

    async def consume(sub_gen):
        async for _ in sub_gen:
            break

    # Start 3 subscriptions as background tasks so they register
    for _ in range(3):
        sub = bus.subscribe(user_id="u1", role="admin", orgs=["org-a"])
        t = asyncio.create_task(consume(sub))
        tasks.append(t)

    # Give all 3 tasks a moment to start and register their subscriber
    await asyncio.sleep(0.05)

    # 4th attempt should raise immediately (before any awaiting)
    with pytest.raises(ConnectionError, match="Too many"):
        bus.subscribe(user_id="u1", role="admin", orgs=["org-a"])

    # Cleanup: publish events to unblock the 3 waiting consumers
    for _ in range(3):
        bus.publish(Event(
            event_type="scan.progress",
            data={"tool": "dependencies", "org": "org-a"},
            org="org-a",
            require_admin=False,
        ))
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_publish_from_sync_thread():
    """publish_sync() should work from a non-async thread."""
    bus = EventBus()
    received = []
    loop = asyncio.get_running_loop()
    bus.set_loop(loop)

    async def consume():
        async for event in bus.subscribe(user_id="u1", role="admin", orgs=["org-a"]):
            received.append(event)
            break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)

    import threading
    def sync_publish():
        bus.publish_sync(Event(
            event_type="scan.completed",
            data={"tool": "dependencies", "org": "org-a"},
            org="org-a",
            require_admin=False,
        ))

    thread = threading.Thread(target=sync_publish)
    thread.start()
    thread.join(timeout=2.0)

    await asyncio.wait_for(task, timeout=1.0)
    assert len(received) == 1
    assert received[0].event_type == "scan.completed"

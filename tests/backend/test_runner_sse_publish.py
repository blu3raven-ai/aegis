# backend/tests/test_runner_sse_publish.py
"""Tests that _sync_progress_to_run publishes scan.progress via EventBus."""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import patch
from src.shared.event_bus import Event, EventBus


@pytest.mark.asyncio
async def test_sync_progress_publishes_event():
    """Verify _sync_progress_to_run publishes scan.progress via EventBus."""
    bus = EventBus()
    loop = asyncio.get_running_loop()
    bus.set_loop(loop)
    received = []

    async def consume():
        _, gen = bus.subscribe(user_id="u1", role="admin", orgs=["test-org"])
        async for event in gen:
            received.append(event)
            break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)

    with patch("src.runner.router.get_event_bus", return_value=bus):
        with patch("src.storage.list_dependencies_runs", return_value=[
            {"id": "run-1", "progress": {"expectedRepos": 10, "scannedRepos": 3, "finishedRepos": 2}}
        ]):
            with patch("src.storage.update_dependencies_run"):
                from src.runner.router import _sync_progress_to_run
                _sync_progress_to_run(
                    {"jobType": "dependencies", "org": "test-org", "runId": "run-1"},
                    ["log line 1"],
                    {"scannedRepos": 5, "finishedRepos": 4, "currentRepo": "repo-a", "stage": "scanning"}
                )

    # Give event loop time to process call_soon_threadsafe
    await asyncio.sleep(0.2)
    await asyncio.wait_for(task, timeout=2.0)
    assert len(received) == 1
    assert received[0].event_type == "scan.progress"
    assert received[0].data["tool"] == "dependencies"
    assert received[0].data["org"] == "test-org"


@pytest.mark.asyncio
async def test_sync_progress_publishes_log_tail_trimmed():
    """Verify log tail is trimmed to last 8 entries in the published event."""
    bus = EventBus()
    loop = asyncio.get_running_loop()
    bus.set_loop(loop)
    received = []

    async def consume():
        _, gen = bus.subscribe(user_id="u2", role="admin", orgs=["org-x"])
        async for event in gen:
            received.append(event)
            break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)

    long_log = [f"line {i}" for i in range(20)]

    with patch("src.runner.router.get_event_bus", return_value=bus):
        with patch("src.storage.list_dependencies_runs", return_value=[
            {"id": "run-2", "progress": {}}
        ]):
            with patch("src.storage.update_dependencies_run"):
                from src.runner.router import _sync_progress_to_run
                _sync_progress_to_run(
                    {"jobType": "dependencies", "org": "org-x", "runId": "run-2"},
                    long_log,
                    {"scannedRepos": 1, "finishedRepos": 0}
                )

    await asyncio.sleep(0.2)
    await asyncio.wait_for(task, timeout=2.0)
    assert len(received) == 1
    assert received[0].data["logTail"] == long_log[-8:]


@pytest.mark.asyncio
async def test_unknown_job_type_does_not_publish():
    """Verify that an unknown job type does not trigger an SSE publish."""
    bus = EventBus()
    loop = asyncio.get_running_loop()
    bus.set_loop(loop)
    received = []

    async def consume():
        _, gen = bus.subscribe(user_id="u3", role="admin", orgs=["org-z"])
        async for event in gen:
            received.append(event)
            break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)

    with patch("src.runner.router.get_event_bus", return_value=bus):
        from src.runner.router import _sync_progress_to_run
        # "unknown_tool" is not in the tool_label map, so no publish should occur
        _sync_progress_to_run(
            {"jobType": "unknown_tool", "org": "org-z", "runId": "run-99"},
            [],
            {"scannedRepos": 1}
        )

    await asyncio.sleep(0.2)
    # task should still be pending (nothing published)
    assert not task.done()
    assert received == []
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

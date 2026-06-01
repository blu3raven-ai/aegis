"""E2E test for Phase 1c parallel orchestration + emit attribution."""
from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest


def test_4_orgs_parallel_emit_all_lifecycle_events():
    """4 orgs scan concurrently; each emits scan.started + scan.completed."""
    from src.shared.scan_orchestration import start_multi_org_scan

    orgs = ["acme-1", "acme-2", "acme-3", "acme-4"]

    all_done = threading.Event()
    call_count = {"n": 0, "lock": threading.Lock()}

    def execute(*args, **kwargs):
        time.sleep(0.15)
        with call_count["lock"]:
            call_count["n"] += 1
            if call_count["n"] == len(orgs):
                all_done.set()
        return {"status": "ok"}

    runtime = MagicMock()
    runtime.probe.return_value = {"active": False}
    runtime.is_cancelled.return_value = False

    create_run_fn = MagicMock()
    exec_fn = MagicMock(side_effect=execute)

    with patch("src.shared.scan_orchestration.emit_scan_started") as started, \
         patch("src.shared.scan_orchestration.emit_scan_completed") as completed:
        t0 = time.perf_counter()
        start_multi_org_scan(
            orgs=orgs,
            runtime=runtime,
            create_run_fn=create_run_fn,
            execute_fn=exec_fn,
            execute_kwargs={},
            source_category="code-repositories",
            tool_label="dependencies",
            skip_connection_check=True,
        )
        finished = all_done.wait(timeout=5.0)
        elapsed = time.perf_counter() - t0

    assert finished, "Not all orgs completed within timeout"

    # 4 × 150ms sequential = 600ms; parallel should be ~150ms
    assert elapsed < 0.45, f"Expected parallel under 450ms, got {elapsed * 1000:.0f}ms"

    started_orgs = {c.kwargs["org_id"] for c in started.call_args_list}
    completed_orgs = {c.kwargs["org_id"] for c in completed.call_args_list}
    assert started_orgs == set(orgs), f"emit_scan_started missing orgs: {set(orgs) - started_orgs}"
    assert completed_orgs == set(orgs), f"emit_scan_completed missing orgs: {set(orgs) - completed_orgs}"

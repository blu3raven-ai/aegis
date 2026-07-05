"""Tests for parallel multi-org orchestration (Phase 1c)."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, call, patch


def _make_runtime(*, active: bool = False, cancelled: bool = False) -> MagicMock:
    runtime = MagicMock()
    runtime.probe.return_value = {"active": active}
    runtime.is_cancelled.return_value = cancelled
    return runtime


def _start(orgs, execute_fn=None, runtime=None, **extra):
    """Helper: invoke start_multi_org_scan and wait for the background thread."""
    from src.shared.scan_orchestration import start_multi_org_scan

    if runtime is None:
        runtime = _make_runtime()
    if execute_fn is None:
        execute_fn = MagicMock(return_value={"status": "ok"})

    create_run_fn = MagicMock()
    done = {"event": __import__("threading").Event()}

    original_execute = execute_fn

    def tracked_execute(*a, **kw):
        result = original_execute(*a, **kw)
        # count down calls; mark done when all orgs have been executed
        return result

    response, status = start_multi_org_scan(
        orgs=orgs,
        runtime=runtime,
        create_run_fn=create_run_fn,
        execute_fn=execute_fn,
        execute_kwargs={},
        source_category="code-repositories",
        tool_label="dependencies",
        skip_connection_check=True,
        **extra,
    )
    assert status == 202
    # Give background thread time to finish
    time.sleep(1.5)
    return response, execute_fn, create_run_fn


def test_multi_org_runs_concurrently_not_sequentially():
    """4 orgs × 300ms each: sequential ≥ 1200ms, parallel ≈ 300ms."""
    from src.shared.scan_orchestration import start_multi_org_scan

    orgs = ["acme-1", "acme-2", "acme-3", "acme-4"]
    runtime = _make_runtime()

    def slow_execute(*args, **kwargs):
        time.sleep(0.3)
        return {"status": "ok"}

    execute_fn = MagicMock(side_effect=slow_execute)
    create_run_fn = MagicMock()

    # time only the background work — we wait until execute has been called 4×
    import threading
    all_done = threading.Event()
    call_count = {"n": 0, "lock": threading.Lock()}
    start_ts: list[float] = []
    end_ts: list[float] = []

    original_side_effect = slow_execute

    def instrumented_execute(*args, **kwargs):
        result = original_side_effect(*args, **kwargs)
        with call_count["lock"]:
            call_count["n"] += 1
            if call_count["n"] == len(orgs):
                all_done.set()
        return result

    execute_fn = MagicMock(side_effect=instrumented_execute)

    t0 = time.perf_counter()
    start_multi_org_scan(
        orgs=orgs,
        runtime=runtime,
        create_run_fn=create_run_fn,
        execute_fn=execute_fn,
        execute_kwargs={},
        source_category="code-repositories",
        tool_label="dependencies",
        skip_connection_check=True,
    )

    # Wait until all 4 calls complete (up to 5s)
    completed = all_done.wait(timeout=5.0)
    elapsed = time.perf_counter() - t0

    assert completed, "Not all orgs completed within timeout"
    assert execute_fn.call_count == 4
    assert elapsed < 0.9, (
        f"Expected parallel execution under 900ms (4×300ms), took {elapsed*1000:.0f}ms — "
        "orgs are likely still running sequentially"
    )


def test_multi_org_preserves_per_org_event_attribution():
    """Each org gets its own emit_scan_started call with the correct org_id."""
    from src.shared.scan_orchestration import start_multi_org_scan

    orgs = ["acme-1", "acme-2", "acme-3"]
    runtime = _make_runtime()
    execute_fn = MagicMock(return_value={"status": "ok"})
    create_run_fn = MagicMock()

    import threading
    all_done = threading.Event()
    call_count = {"n": 0, "lock": threading.Lock()}

    def tracked_execute(*args, **kwargs):
        result = {"status": "ok"}
        with call_count["lock"]:
            call_count["n"] += 1
            if call_count["n"] == len(orgs):
                all_done.set()
        return result

    execute_fn = MagicMock(side_effect=tracked_execute)

    with patch("src.shared.scan_orchestration.emit_scan_started") as mock_emit:
        start_multi_org_scan(
            orgs=orgs,
            runtime=runtime,
            create_run_fn=create_run_fn,
            execute_fn=execute_fn,
            execute_kwargs={},
            source_category="code-repositories",
            tool_label="dependencies",
            skip_connection_check=True,
        )
        all_done.wait(timeout=5.0)

    emitted_orgs = [c.kwargs["org_id"] for c in mock_emit.call_args_list]
    assert set(emitted_orgs) == set(orgs), (
        f"Each org should have its own emit_scan_started; got {emitted_orgs}"
    )
    assert len(emitted_orgs) == len(orgs), (
        f"Expected {len(orgs)} emit_scan_started calls, got {len(emitted_orgs)}"
    )


def test_multi_org_failure_in_one_org_does_not_block_others():
    """An exception in one org's execute_fn must not prevent other orgs from completing."""
    from src.shared.scan_orchestration import start_multi_org_scan

    orgs = ["acme-1", "acme-2", "acme-3", "acme-4"]
    runtime = _make_runtime()
    create_run_fn = MagicMock()

    completed: list[str] = []
    import threading
    lock = threading.Lock()
    all_non_failing_done = threading.Event()

    def execute_fn(*args, **kwargs):
        # first positional arg is org_name
        org = args[0] if args else kwargs.get("org")
        if org == "acme-2":
            raise RuntimeError("simulated failure for acme-2")
        with lock:
            completed.append(org)
            if len(completed) == 3:  # 3 non-failing orgs
                all_non_failing_done.set()
        return {"status": "ok"}

    start_multi_org_scan(
        orgs=orgs,
        runtime=runtime,
        create_run_fn=create_run_fn,
        execute_fn=execute_fn,
        execute_kwargs={},
        source_category="code-repositories",
        tool_label="dependencies",
        skip_connection_check=True,
    )

    finished = all_non_failing_done.wait(timeout=5.0)
    assert finished, (
        f"Not all non-failing orgs completed. Completed: {completed}. "
        "A failure in one org may be blocking siblings."
    )
    assert set(completed) == {"acme-1", "acme-3", "acme-4"}, (
        f"Expected acme-1, acme-3, acme-4 to complete; got {completed}"
    )

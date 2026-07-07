"""Tests for the ProgressEmitter helper used by all four scanners."""
from __future__ import annotations

import threading

import pytest

from runner.scanners._shared import ProgressEmitter


def _capture():
    events: list[dict] = []

    def on_progress(log_tail, progress):
        # Snapshot the dict so later mutations don't leak into assertions.
        events.append(dict(progress))

    return events, on_progress


def test_emits_starting_stage():
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=2)
    emitter.starting()

    assert events[-1]["stage"] == "starting"
    assert events[-1]["expectedRepos"] == 2
    assert events[-1]["scannedRepos"] == 0
    assert events[-1]["finishedRepos"] == 0


def test_scanning_increments_scanned_and_sets_current_repo():
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=2)

    emitter.scanning("repo-a")
    snap = events[-1]
    assert snap["stage"] == "scanning"
    assert snap["scannedRepos"] == 1
    assert snap["currentRepo"] == "repo-a"

    emitter.scanning("repo-b")
    snap = events[-1]
    assert snap["scannedRepos"] == 2
    assert snap["currentRepo"] == "repo-b"


def test_finished_increments_and_clears_current_repo():
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=2)

    emitter.scanning("repo-a")
    emitter.finished("repo-a")

    snap = events[-1]
    assert snap["finishedRepos"] == 1
    assert "currentRepo" not in snap


def test_finished_keeps_unrelated_current_repo():
    """If two repos run concurrently, finishing one shouldn't clear the other."""
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=2)

    emitter.scanning("repo-a")
    emitter.scanning("repo-b")
    emitter.finished("repo-a")

    snap = events[-1]
    assert snap["currentRepo"] == "repo-b"
    assert snap["finishedRepos"] == 1


def test_normalizing_clears_current_repo():
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=1)

    emitter.scanning("repo-a")
    emitter.normalizing()

    snap = events[-1]
    assert snap["stage"] == "normalizing"
    assert "currentRepo" not in snap


def test_done_sets_finished_to_expected_and_stage_done():
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=3)

    emitter.scanning("a")
    emitter.done()

    snap = events[-1]
    assert snap["stage"] == "done"
    assert snap["finishedRepos"] == 3
    assert snap["expectedRepos"] == 3
    assert "currentRepo" not in snap


def test_counters_are_monotonic_non_decreasing():
    """Across the full lifecycle, scanned and finished must never decrease."""
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=3)

    emitter.starting()
    emitter.scanning("a")
    emitter.scanning("b")
    emitter.finished("a")
    emitter.scanning("c")
    emitter.finished("b")
    emitter.finished("c")
    emitter.normalizing()
    emitter.done()

    scanned_seq = [e["scannedRepos"] for e in events]
    finished_seq = [e["finishedRepos"] for e in events]
    assert scanned_seq == sorted(scanned_seq)
    assert finished_seq == sorted(finished_seq)


def test_none_callback_is_noop():
    """on_progress=None must not raise and must not break state transitions."""
    emitter = ProgressEmitter(None, expected=2)
    emitter.starting()
    emitter.scanning("a")
    emitter.finished("a")
    emitter.normalizing()
    emitter.done()  # no exception


def test_callback_exception_is_swallowed():
    """A raising on_progress must never abort the scan."""
    def bad(log_tail, progress):
        raise RuntimeError("boom")

    emitter = ProgressEmitter(bad, expected=1)
    # Each of these would otherwise propagate.
    emitter.starting()
    emitter.scanning("a")
    emitter.finished("a")
    emitter.normalizing()
    emitter.done()


def test_thread_safety_under_concurrent_scanning_and_finishing():
    """Multiple threads driving scanning()/finished() must converge to a
    consistent final state with monotonic counters."""
    events, cb = _capture()
    n = 50
    emitter = ProgressEmitter(cb, expected=n)

    barrier = threading.Barrier(n)

    def worker(i: int) -> None:
        barrier.wait()
        emitter.scanning(f"repo-{i}")
        emitter.finished(f"repo-{i}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = events[-1]
    assert final["scannedRepos"] == n
    assert final["finishedRepos"] == n

    scanned_seq = [e["scannedRepos"] for e in events]
    finished_seq = [e["finishedRepos"] for e in events]
    assert scanned_seq == sorted(scanned_seq)
    assert finished_seq == sorted(finished_seq)


def test_expected_zero_is_supported():
    """Empty scan path: expected=0, done() yields finished=0/expected=0."""
    events, cb = _capture()
    emitter = ProgressEmitter(cb, expected=0)
    emitter.done()

    snap = events[-1]
    assert snap["expectedRepos"] == 0
    assert snap["finishedRepos"] == 0
    assert snap["stage"] == "done"


def test_negative_expected_clamped_to_zero():
    emitter = ProgressEmitter(None, expected=-5)
    # Internal state not exposed; calling done() must yield finished=0.
    captured: list[dict] = []
    emitter._on_progress = lambda lt, p: captured.append(dict(p))
    emitter.done()
    assert captured[-1]["finishedRepos"] == 0
    assert captured[-1]["expectedRepos"] == 0

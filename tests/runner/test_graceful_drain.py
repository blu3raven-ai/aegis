"""Tests for graceful drain on SIGTERM (Phase 35).

All tests are unit-level and require no external services.
"""
from __future__ import annotations

import os
import signal
import sys
import threading
import time

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from runner.core.graceful_drain import GracefulDrainManager


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

class TestInitialState:
    def test_not_draining_initially(self):
        mgr = GracefulDrainManager()
        assert mgr.is_draining() is False

    def test_in_flight_count_zero_initially(self):
        mgr = GracefulDrainManager()
        assert mgr.in_flight_count == 0


# ---------------------------------------------------------------------------
# trigger_drain / is_draining
# ---------------------------------------------------------------------------

class TestTriggerDrain:
    def test_trigger_sets_draining(self):
        mgr = GracefulDrainManager()
        mgr.trigger_drain()
        assert mgr.is_draining() is True

    def test_trigger_is_idempotent(self):
        mgr = GracefulDrainManager()
        mgr.trigger_drain()
        mgr.trigger_drain()
        assert mgr.is_draining() is True


# ---------------------------------------------------------------------------
# SIGTERM handler
# ---------------------------------------------------------------------------

class TestSignalHandler:
    def test_sigterm_sets_draining(self):
        """install_handler + SIGTERM must set draining. Only valid in main thread."""
        mgr = GracefulDrainManager()
        mgr.install_handler()
        # Send SIGTERM to ourselves
        os.kill(os.getpid(), signal.SIGTERM)
        # Give signal delivery a moment to run
        time.sleep(0.05)
        assert mgr.is_draining() is True

    def test_sigint_sets_draining(self):
        mgr = GracefulDrainManager()
        mgr.install_handler()
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)
        assert mgr.is_draining() is True


# ---------------------------------------------------------------------------
# track_job_start / track_job_end
# ---------------------------------------------------------------------------

class TestJobTracking:
    def test_start_increments_count(self):
        mgr = GracefulDrainManager()
        mgr.track_job_start()
        assert mgr.in_flight_count == 1

    def test_end_decrements_count(self):
        mgr = GracefulDrainManager()
        mgr.track_job_start()
        mgr.track_job_start()
        mgr.track_job_end()
        assert mgr.in_flight_count == 1

    def test_multiple_starts_and_ends(self):
        mgr = GracefulDrainManager()
        for _ in range(5):
            mgr.track_job_start()
        for _ in range(3):
            mgr.track_job_end()
        assert mgr.in_flight_count == 2

    def test_end_does_not_go_below_zero(self):
        """Spurious end call must not produce negative count."""
        mgr = GracefulDrainManager()
        mgr.track_job_end()  # no start
        assert mgr.in_flight_count == 0

    def test_thread_safe_concurrent_tracking(self):
        mgr = GracefulDrainManager()
        n = 50

        def start_then_end():
            mgr.track_job_start()
            time.sleep(0.001)
            mgr.track_job_end()

        threads = [threading.Thread(target=start_then_end) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert mgr.in_flight_count == 0


# ---------------------------------------------------------------------------
# wait_for_drain
# ---------------------------------------------------------------------------

class TestWaitForDrain:
    def test_returns_true_when_already_zero(self):
        mgr = GracefulDrainManager(drain_timeout=5)
        result = mgr.wait_for_drain()
        assert result is True

    def test_returns_true_after_jobs_finish(self):
        mgr = GracefulDrainManager(drain_timeout=5)
        mgr.track_job_start()

        def finish_soon():
            time.sleep(0.1)
            mgr.track_job_end()

        threading.Thread(target=finish_soon, daemon=True).start()
        result = mgr.wait_for_drain()
        assert result is True

    def test_returns_false_on_timeout(self):
        mgr = GracefulDrainManager(drain_timeout=0)
        mgr.track_job_start()  # never ended
        # drain_timeout=0 means immediate expiry
        result = mgr.wait_for_drain()
        assert result is False

    def test_returns_false_when_jobs_dont_finish_in_time(self):
        mgr = GracefulDrainManager(drain_timeout=1)
        mgr.track_job_start()
        # job never calls track_job_end within 1 second
        start = time.monotonic()
        result = mgr.wait_for_drain()
        elapsed = time.monotonic() - start
        assert result is False
        # Should have waited roughly drain_timeout seconds
        assert elapsed >= 0.9

    def test_drains_multiple_in_flight_jobs(self):
        mgr = GracefulDrainManager(drain_timeout=5)
        n = 3
        for _ in range(n):
            mgr.track_job_start()

        def finish(delay):
            time.sleep(delay)
            mgr.track_job_end()

        for i in range(n):
            threading.Thread(target=finish, args=(0.05 * (i + 1),), daemon=True).start()

        result = mgr.wait_for_drain()
        assert result is True
        assert mgr.in_flight_count == 0

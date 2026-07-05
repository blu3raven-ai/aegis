"""Integration tests: agent rejects new jobs when draining (Phase 35).

Tests verify that _pull_and_dispatch() skips dispatching once drain is active,
and that stop() triggers drain + waits for in-flight count to reach zero.
All tests mock I/O so they run without Docker or a live backend.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from runner.agent import RunnerAgent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _minimal_config() -> dict:
    return {
        "portalUrl": "http://localhost:9999",
        "authToken": "test-token",
        "name": "test-runner",
        "maxConcurrent": 4,
    }


def _make_agent() -> RunnerAgent:
    return RunnerAgent(_minimal_config())


# ---------------------------------------------------------------------------
# _pull_and_dispatch blocked while draining
# ---------------------------------------------------------------------------

class TestPullAndDispatchDuringDrain:
    def test_no_dispatch_when_draining(self):
        """_pull_and_dispatch must return False without polling when draining."""
        agent = _make_agent()
        mock_pool = MagicMock()
        agent._pool = mock_pool
        agent._drain.trigger_drain()

        result = agent._pull_and_dispatch()

        assert result is False
        mock_pool.submit.assert_not_called()

    def test_dispatches_when_not_draining(self):
        """_pull_and_dispatch proceeds normally when not draining."""
        agent = _make_agent()
        mock_future = MagicMock()
        mock_pool = MagicMock()
        mock_pool.submit.return_value = mock_future
        agent._pool = mock_pool

        fake_job = {
            "jobId": "job-abc",
            "type": "dependencies_scanning",
            "org": "example-org",
            "runId": "run-1",
        }

        with patch.object(agent, "_poll_job", return_value=fake_job):
            result = agent._pull_and_dispatch()

        assert result is True
        mock_pool.submit.assert_called_once()

    def test_dispatch_rejected_after_drain_triggered(self):
        """Jobs queued after trigger_drain() are not dispatched."""
        agent = _make_agent()
        mock_pool = MagicMock()
        agent._pool = mock_pool

        fake_job = {"jobId": "job-xyz", "type": "secret_scanning", "org": "example-org", "runId": "run-2"}

        with patch.object(agent, "_poll_job", return_value=fake_job):
            # Before drain: dispatch works
            result_before = agent._pull_and_dispatch()

        agent._drain.trigger_drain()

        with patch.object(agent, "_poll_job", return_value=fake_job):
            # After drain: dispatch blocked
            result_after = agent._pull_and_dispatch()

        assert result_before is True
        assert result_after is False


# ---------------------------------------------------------------------------
# stop() triggers drain
# ---------------------------------------------------------------------------

class TestStopTriggersDrain:
    def test_stop_sets_draining(self):
        agent = _make_agent()
        assert not agent._drain.is_draining()

        agent.stop()

        assert agent._drain.is_draining()

    def test_stop_sets_internal_stop_event(self):
        agent = _make_agent()
        agent.stop()
        assert agent._stop.is_set()

    def test_stop_waits_for_in_flight_to_finish(self):
        """stop() should wait for in-flight count to reach 0."""
        agent = _make_agent()
        agent._drain.track_job_start()  # simulate one in-flight job

        def finish_job():
            time.sleep(0.15)
            agent._drain.track_job_end()

        threading.Thread(target=finish_job, daemon=True).start()

        start = time.monotonic()
        agent.stop()
        elapsed = time.monotonic() - start

        # Should have waited for the job to finish (~0.15s)
        assert elapsed >= 0.1
        assert agent._drain.in_flight_count == 0

    def test_stop_completes_cleanly(self):
        agent = _make_agent()
        agent.stop()


# ---------------------------------------------------------------------------
# Drain manager wired into agent correctly
# ---------------------------------------------------------------------------

class TestDrainManagerIntegration:
    def test_agent_has_drain_manager(self):
        from runner.core.graceful_drain import GracefulDrainManager
        agent = _make_agent()
        assert isinstance(agent._drain, GracefulDrainManager)

    def test_drain_timeout_defaults_to_300(self, monkeypatch):
        monkeypatch.delenv("RUNNER_DRAIN_TIMEOUT_SECONDS", raising=False)
        agent = _make_agent()
        assert agent._drain._drain_timeout == 300

    def test_drain_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("RUNNER_DRAIN_TIMEOUT_SECONDS", "60")
        agent = RunnerAgent(_minimal_config())
        assert agent._drain._drain_timeout == 60

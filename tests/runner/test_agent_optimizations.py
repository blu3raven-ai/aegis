"""Cached disk-space check + async cleanup."""
from __future__ import annotations

import concurrent.futures
import time
from unittest.mock import patch

from runner.agent import RunnerAgent


def _agent() -> RunnerAgent:
    return RunnerAgent({"portalUrl": "https://x", "authToken": "t"})


def test_disk_check_cached_within_ttl():
    agent = _agent()
    try:
        with patch("runner.agent.shutil.disk_usage") as mock:
            mock.return_value = type("DU", (), {"free": 10 * 1024**3})
            agent._cached_disk_free_gb()
            agent._cached_disk_free_gb()
            agent._cached_disk_free_gb()
            assert mock.call_count == 1
    finally:
        agent._http.close()
        agent._cleanup_pool.shutdown(wait=False)


def test_disk_check_refreshes_after_ttl():
    agent = _agent()
    try:
        with patch("runner.agent.shutil.disk_usage") as mock:
            mock.return_value = type("DU", (), {"free": 10 * 1024**3})
            agent._cached_disk_free_gb()
            agent._disk_check_at = time.monotonic() - 100  # past TTL
            agent._cached_disk_free_gb()
            assert mock.call_count == 2
    finally:
        agent._http.close()
        agent._cleanup_pool.shutdown(wait=False)


def test_disk_check_returns_generous_fallback_on_oserror():
    agent = _agent()
    try:
        with patch("runner.agent.shutil.disk_usage", side_effect=OSError("boom")):
            free = agent._cached_disk_free_gb()
            assert free == 999.0
    finally:
        agent._http.close()
        agent._cleanup_pool.shutdown(wait=False)


def test_cleanup_pool_initialized():
    agent = _agent()
    try:
        assert isinstance(
            agent._cleanup_pool, concurrent.futures.ThreadPoolExecutor
        )
    finally:
        agent._http.close()
        agent._cleanup_pool.shutdown(wait=False)


def test_stop_shuts_down_cleanup_pool():
    """Source-inspect stop() to verify shutdown is wired in."""
    import inspect
    src = inspect.getsource(RunnerAgent.stop)
    assert "self._cleanup_pool.shutdown" in src

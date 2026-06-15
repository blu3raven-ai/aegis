"""Unit tests for the five background-job triggers wired into AutoRerunScheduler."""
from __future__ import annotations

import os
import time
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)


def _wait_for_thread(name_prefix: str, timeout: float = 1.0) -> None:
    """Wait until any thread whose name starts with the prefix has exited."""
    import threading as _t

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(t.is_alive() and t.name.startswith(name_prefix) for t in _t.enumerate()):
            return
        time.sleep(0.02)


def test_trigger_kev_refresh_spawns_thread_and_calls_job():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.kev_refresh.refresh_kev_catalog", return_value={"fetched": 0, "new": 0}) as mock_job:
        scheduler._trigger_kev_refresh()
        _wait_for_thread("kev-refresh")
        assert mock_job.called


def test_trigger_kev_refresh_swallows_exception():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.kev_refresh.refresh_kev_catalog", side_effect=RuntimeError("fetch failed")):
        scheduler._trigger_kev_refresh()  # must not raise
        _wait_for_thread("kev-refresh")


def test_trigger_epss_refresh_spawns_thread_and_calls_job():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.epss_refresh.refresh_epss_scores", return_value={"fetched": 0, "upserted": 0}) as mock_job:
        scheduler._trigger_epss_refresh()
        _wait_for_thread("epss-refresh")
        assert mock_job.called


def test_trigger_sla_recompute_spawns_thread_and_calls_job():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.sla_recompute.trigger_sla_recompute") as mock_job:
        scheduler._trigger_sla_recompute(["org-a", "org-b"])
        _wait_for_thread("sla-recompute")
        mock_job.assert_called_once_with(["org-a", "org-b"])


def test_trigger_sla_recompute_skips_when_no_orgs():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.sla_recompute.trigger_sla_recompute") as mock_job:
        scheduler._trigger_sla_recompute([])
        time.sleep(0.05)
        assert not mock_job.called


def test_trigger_scanner_coverage_recompute_spawns_thread_and_calls_job():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.scanner_coverage_recompute.trigger_scanner_coverage_recompute") as mock_job:
        scheduler._trigger_scanner_coverage_recompute(["org-a"])
        _wait_for_thread("scanner-coverage-recompute")
        mock_job.assert_called_once_with(["org-a"])


def test_trigger_scanner_coverage_recompute_skips_when_no_orgs():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.scanner_coverage_recompute.trigger_scanner_coverage_recompute") as mock_job:
        scheduler._trigger_scanner_coverage_recompute([])
        time.sleep(0.05)
        assert not mock_job.called


def test_trigger_data_retention_recompute_spawns_thread_and_calls_job():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.data_retention_recompute.trigger_data_retention_recompute") as mock_job:
        scheduler._trigger_data_retention_recompute(["org-a", "org-b"])
        _wait_for_thread("data-retention-recompute")
        mock_job.assert_called_once_with(["org-a", "org-b"])


def test_trigger_data_retention_recompute_skips_when_no_orgs():
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch("src.jobs.data_retention_recompute.trigger_data_retention_recompute") as mock_job:
        scheduler._trigger_data_retention_recompute([])
        time.sleep(0.05)
        assert not mock_job.called

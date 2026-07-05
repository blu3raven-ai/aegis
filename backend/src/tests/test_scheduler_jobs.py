"""Unit tests for the five background-job triggers wired into AutoRerunScheduler."""
from __future__ import annotations

import os
import time
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)


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


def test_tick_feeds_sla_recompute_asset_ids_not_org_names(monkeypatch):
    """Regression: the SLA evaluator filters findings by ``asset_id``, so the
    hourly tick must hand it asset ids — not the org names that drive the
    per-source scan triggers. Feeding org names matched no findings and left
    ``finding_sla_status`` empty."""
    import src.assets.service as assets_svc
    import src.scheduler as sched
    import src.shared.config as cfg

    monkeypatch.setattr(cfg, "read_app_config", lambda: {"tools": {}})
    monkeypatch.setattr(cfg, "get_orgs_from_source_connections", lambda: ["acme-org"])
    monkeypatch.setattr(assets_svc, "get_all_asset_ids", lambda: ["asset-1", "asset-2"])
    # Fire only the hourly SLA cron; every other scheduled branch stays inert.
    monkeypatch.setattr(sched, "_matches_cron", lambda expr, now: expr == "0 * * * *")

    scheduler = sched.AutoRerunScheduler()
    monkeypatch.setattr(scheduler, "_tick_scheduled_reports", lambda now: None)
    monkeypatch.setattr(scheduler, "_take_posture_snapshots", lambda: None)

    captured: dict = {}
    monkeypatch.setattr(
        scheduler, "_trigger_sla_recompute", lambda ids: captured.__setitem__("ids", ids)
    )

    scheduler._tick()

    assert captured["ids"] == ["asset-1", "asset-2"]


def _assert_tick_feeds_asset_ids(monkeypatch, *, cron: str, method: str):
    """Fire only `cron` and assert the named `_trigger_*` method receives asset
    ids (from get_all_asset_ids), not the org names from source connections."""
    import src.assets.service as assets_svc
    import src.scheduler as sched
    import src.shared.config as cfg

    monkeypatch.setattr(cfg, "read_app_config", lambda: {"tools": {}})
    monkeypatch.setattr(cfg, "get_orgs_from_source_connections", lambda: ["acme-org"])
    monkeypatch.setattr(assets_svc, "get_all_asset_ids", lambda: ["asset-1", "asset-2"])
    monkeypatch.setattr(sched, "_matches_cron", lambda expr, now: expr == cron)

    scheduler = sched.AutoRerunScheduler()
    monkeypatch.setattr(scheduler, "_tick_scheduled_reports", lambda now: None)
    monkeypatch.setattr(scheduler, "_take_posture_snapshots", lambda: None)

    captured: dict = {}
    monkeypatch.setattr(scheduler, method, lambda ids: captured.__setitem__("ids", ids))

    scheduler._tick()

    assert captured["ids"] == ["asset-1", "asset-2"]


def test_tick_feeds_scanner_coverage_recompute_asset_ids(monkeypatch):
    """Regression: scanner-coverage evaluates findings by asset_id; the daily
    tick must feed asset ids, not org names."""
    _assert_tick_feeds_asset_ids(
        monkeypatch, cron="0 4 * * *", method="_trigger_scanner_coverage_recompute"
    )


def test_tick_feeds_data_retention_recompute_asset_ids(monkeypatch):
    """Regression: data-retention evaluates scans by asset_id; the daily tick
    must feed asset ids, not org names (org names matched nothing, so retention
    rules never ran)."""
    _assert_tick_feeds_asset_ids(
        monkeypatch, cron="30 4 * * *", method="_trigger_data_retention_recompute"
    )

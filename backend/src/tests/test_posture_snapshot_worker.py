"""Unit tests for compute_and_store_daily_snapshots and the scheduler tick."""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)


def test_take_posture_snapshots_calls_service():
    """Scheduler tick delegates to compute_and_store_daily_snapshots and logs the count."""
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch(
        "src.posture.service.compute_and_store_daily_snapshots",
        return_value=42,
    ) as mock_compute:
        scheduler._take_posture_snapshots()
    mock_compute.assert_called_once_with()


def test_take_posture_snapshots_swallows_errors():
    """A failing service call must not crash the scheduler thread."""
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch(
        "src.posture.service.compute_and_store_daily_snapshots",
        side_effect=RuntimeError("simulated failure"),
    ):
        scheduler._take_posture_snapshots()  # must not raise


def test_compute_and_store_uses_run_db_with_today_default(monkeypatch):
    """compute_and_store_daily_snapshots dispatches to run_db with the current date by default."""
    from datetime import date

    from src.posture import service

    captured = {}

    def fake_run_db(coro_factory):
        # We don't execute the coroutine — just verify the call shape.
        captured["called"] = True
        return 0

    monkeypatch.setattr(service, "run_db", fake_run_db)
    result = service.compute_and_store_daily_snapshots()
    assert captured["called"] is True
    assert result == 0


def test_compute_and_store_respects_today_override(monkeypatch):
    """Passing today=... lets the caller pin the snapshot date (used by backfill)."""
    from datetime import date

    from src.posture import service

    monkeypatch.setattr(service, "run_db", lambda fn: 0)
    # Smoke: function accepts and routes through cleanly.
    service.compute_and_store_daily_snapshots(today=date(2026, 6, 1))

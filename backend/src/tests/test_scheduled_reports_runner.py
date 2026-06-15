"""Unit tests for src.reports.runner."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)


def _fake_schedule(**overrides):
    from src.db.models import ScheduledReport
    sr = ScheduledReport(
        id=overrides.get("id", 1),
        name=overrides.get("name", "Weekly findings"),
        report_type=overrides.get("report_type", "findings"),
        format=overrides.get("format", "pdf"),
        schedule_type=overrides.get("schedule_type", "simple"),
        schedule_value=overrides.get("schedule_value", "09:00"),
        filters=overrides.get("filters", {"asset_ids": ["a-1"], "severity": ["critical"]}),
        destination_ids=overrides.get("destination_ids", [10]),
        created_by=overrides.get("created_by", "u@example.com"),
        enabled=overrides.get("enabled", True),
        last_run_at=overrides.get("last_run_at"),
    )
    return sr


def _fake_report():
    from src.db.models import Report
    return Report(
        id=99, title="Weekly findings", report_type="findings", format="pdf",
        status="completed", filters={}, row_count=10, file_size_bytes=2000,
        created_by="u@example.com",
        expires_at=datetime(2026, 7, 14, tzinfo=timezone.utc),
        storage_key="u@example.com/99.pdf",
    )


def test_skip_when_not_matching_now():
    from src.reports import runner
    now = datetime(2026, 6, 14, 8, 0, tzinfo=timezone.utc)
    schedule = _fake_schedule(schedule_value="09:00")  # different minute
    with (
        patch.object(runner, "_load_enabled_schedules", return_value=[schedule]),
        patch.object(runner, "_mark_run") as mark,
    ):
        n = runner.run_due_schedules(now=now)
    assert n == 0
    mark.assert_not_called()


def test_runs_due_schedule_and_marks_success():
    from src.reports import runner
    now = datetime(2026, 6, 14, 9, 0, tzinfo=timezone.utc)
    schedule = _fake_schedule(schedule_value="09:00")
    report = _fake_report()

    with (
        patch.object(runner, "_load_enabled_schedules", return_value=[schedule]),
        patch("src.reports.service.generate_report", return_value=report),
        patch("src.reports.service.get_download_url", return_value="https://signed/url"),
        patch.object(runner, "_deliver") as deliver,
        patch.object(runner, "_mark_run") as mark,
    ):
        n = runner.run_due_schedules(now=now)

    assert n == 1
    deliver.assert_called_once()
    args, kwargs = mark.call_args
    assert kwargs["status"] == "success"
    assert kwargs["error"] is None


def test_failure_records_status_failed():
    from src.reports import runner
    now = datetime(2026, 6, 14, 9, 0, tzinfo=timezone.utc)
    schedule = _fake_schedule(schedule_value="09:00")

    def _boom(**_kw):
        raise RuntimeError("simulated")

    with (
        patch.object(runner, "_load_enabled_schedules", return_value=[schedule]),
        patch("src.reports.service.generate_report", side_effect=_boom),
        patch.object(runner, "_deliver"),
        patch.object(runner, "_mark_run") as mark,
    ):
        n = runner.run_due_schedules(now=now)

    assert n == 1
    args, kwargs = mark.call_args
    assert kwargs["status"] == "failed"
    assert "simulated" in (kwargs["error"] or "")


def test_recent_run_within_55s_is_skipped():
    from src.reports import runner
    now = datetime(2026, 6, 14, 9, 0, 30, tzinfo=timezone.utc)
    last_run = now - timedelta(seconds=30)
    schedule = _fake_schedule(schedule_value="09:00", last_run_at=last_run)

    with (
        patch.object(runner, "_load_enabled_schedules", return_value=[schedule]),
        patch("src.reports.service.generate_report") as gen,
        patch.object(runner, "_mark_run") as mark,
    ):
        n = runner.run_due_schedules(now=now)

    assert n == 0
    gen.assert_not_called()
    mark.assert_not_called()


def test_strips_asset_ids_from_filters_when_calling_generate():
    from src.reports import runner
    now = datetime(2026, 6, 14, 9, 0, tzinfo=timezone.utc)
    schedule = _fake_schedule(
        schedule_value="09:00",
        filters={"asset_ids": ["a-1", "a-2"], "severity": ["critical"]},
    )
    report = _fake_report()

    captured: dict = {}
    def _gen(**kw):
        captured.update(kw)
        return report

    with (
        patch.object(runner, "_load_enabled_schedules", return_value=[schedule]),
        patch("src.reports.service.generate_report", side_effect=_gen),
        patch("src.reports.service.get_download_url", return_value="https://signed/url"),
        patch.object(runner, "_deliver"),
        patch.object(runner, "_mark_run"),
    ):
        runner.run_due_schedules(now=now)

    assert captured["asset_ids"] == ["a-1", "a-2"]
    assert captured["filters"] == {"severity": ["critical"]}  # asset_ids stripped


def test_tick_scheduler_dispatches_to_runner():
    from src.scheduler import AutoRerunScheduler
    scheduler = AutoRerunScheduler()
    now = datetime(2026, 6, 14, 9, 0, tzinfo=timezone.utc)
    with patch("src.reports.runner.run_due_schedules", return_value=3) as mock_run:
        scheduler._tick_scheduled_reports(now)
    mock_run.assert_called_once_with(now=now)


def test_tick_scheduler_swallows_exceptions():
    from src.scheduler import AutoRerunScheduler
    scheduler = AutoRerunScheduler()
    now = datetime(2026, 6, 14, 9, 0, tzinfo=timezone.utc)
    with patch("src.reports.runner.run_due_schedules", side_effect=RuntimeError("nope")):
        scheduler._tick_scheduled_reports(now)  # must not raise

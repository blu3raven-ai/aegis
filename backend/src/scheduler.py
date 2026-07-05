from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _field_match(field: str, value: int, min_val: int = 0) -> bool:
    if field == "*":
        return True
    if "," in field:
        return any(_field_match(f.strip(), value, min_val) for f in field.split(","))
    if "/" in field:
        base, step = field.split("/", 1)
        start = min_val if base == "*" else int(base)
        return value >= start and (value - start) % int(step) == 0
    if "-" in field:
        a, b = field.split("-", 1)
        return int(a) <= value <= int(b)
    return field.isdigit() and int(field) == value


def _matches_cron(expression: str, now: datetime) -> bool:
    try:
        parts = expression.strip().split()
        if len(parts) != 5:
            return False
        minute, hour, dom, month, dow = parts
        # Cron dow: 0=Sunday. Python weekday(): 0=Monday. Convert: Mon=1..Sat=6,Sun=0.
        cron_dow = (now.weekday() + 1) % 7
        return (
            _field_match(minute, now.minute)
            and _field_match(hour, now.hour)
            and _field_match(dom, now.day, 1)
            and _field_match(month, now.month, 1)
            and _field_match(dow, cron_dow)
        )
    except Exception:
        logger.warning("Failed to parse cron expression %r", expression)
        return False


def _matches_schedule(schedule_type: str, schedule_value: str, now: datetime) -> bool:
    if schedule_type == "simple":
        try:
            h, m = schedule_value.strip().split(":")
            return now.hour == int(h) and now.minute == int(m)
        except Exception:
            logger.warning("Failed to parse simple schedule %r", schedule_value)
            return False
    if schedule_type == "cron":
        return _matches_cron(schedule_value, now)
    return False


class AutoRerunScheduler:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="auto-rerun-scheduler"
        )
        self._thread.start()
        logger.info("Auto-rerun scheduler started")

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        now = datetime.now()
        time.sleep(60 - now.second - now.microsecond / 1_000_000)

        while self._running:
            try:
                self._tick()
            except Exception:
                logger.exception("Scheduler tick error")
            time.sleep(60)

    def _tick(self) -> None:
        now = datetime.now()

        # Per-scanner reruns are driven per source (scanAutoEnabled + schedule),
        # handled below in _tick_source_schedules.

        # Midnight UTC: write daily posture snapshots
        if now.hour == 0 and now.minute == 0:
            self._take_posture_snapshots()

        # Scheduled reports: check every minute
        self._tick_scheduled_reports(now)

        # Daily CISA KEV catalog refresh (03:00)
        if _matches_cron("0 3 * * *", now):
            self._trigger_kev_refresh()

        # Daily FIRST.org EPSS scores refresh (03:15, after KEV so CVE rows already exist)
        if _matches_cron("15 3 * * *", now):
            self._trigger_epss_refresh()

        # Daily OSV catalog refresh + dispatch (02:00 — earliest of the daily jobs
        # so its dispatch can ride the dependency-scan rerun if both fire today)
        if _matches_cron("0 2 * * *", now):
            self._trigger_osv_refresh()

        # Asset-scoped recomputes evaluate findings/scans by asset_id, so they
        # need asset ids — not the org names that drive the per-source scan
        # triggers above. Resolve once, only when at least one is due (SLA hourly;
        # scanner-coverage 04:00; data-retention 04:30, offset so the two heavy
        # nightly evaluators don't contend for the DB at the same minute).
        sla_due = _matches_cron("0 * * * *", now)
        coverage_due = _matches_cron("0 4 * * *", now)
        retention_due = _matches_cron("30 4 * * *", now)
        if sla_due or coverage_due or retention_due:
            from src.assets.service import get_all_asset_ids
            asset_ids = get_all_asset_ids()
            if sla_due:
                self._trigger_sla_recompute(asset_ids)
            if coverage_due:
                self._trigger_scanner_coverage_recompute(asset_ids)
            if retention_due:
                self._trigger_data_retention_recompute(asset_ids)

        # Per-source sync / auto-scan schedules (preset or cron, configured per source)
        self._tick_source_schedules(now)

    def _tick_source_schedules(self, now: datetime) -> None:
        from src.sources import store as sources_store
        from src.sources.scheduling import is_schedule_due

        try:
            connections = sources_store.list_connections_with_secrets()
        except Exception:
            logger.exception("Source schedule tick: failed to load connections")
            return

        for conn in connections:
            try:
                if is_schedule_due(
                    conn.get("syncScheduleMode", "preset"),
                    conn.get("syncSchedule", "6h"),
                    conn.get("syncScheduleCron"),
                    now,
                ):
                    self._run_source_sync(conn.get("id"))

                if conn.get("scanAutoEnabled") and is_schedule_due(
                    conn.get("scanScheduleMode", "preset"),
                    conn.get("scanSchedulePreset", "24h"),
                    conn.get("scanScheduleCron"),
                    now,
                ):
                    self._run_source_scan(conn)
            except Exception:
                logger.exception("Source schedule tick failed for %s", conn.get("id"))

    def _run_source_sync(self, connection_id: str) -> None:
        import asyncio
        import threading

        def _run() -> None:
            try:
                from src.sources.triggers import run_source_sync
                asyncio.run(run_source_sync(connection_id))
                logger.info("Scheduled source sync complete: %s", connection_id)
            except Exception:
                logger.exception("Scheduled source sync failed: %s", connection_id)

        threading.Thread(target=_run, daemon=True, name="source-sync").start()

    def _run_source_scan(self, connection: dict[str, Any]) -> None:
        import threading

        def _run() -> None:
            try:
                from src.sources.triggers import dispatch_source_scan
                queued = dispatch_source_scan(connection, run_prefix="scheduled")
                logger.info(
                    "Scheduled source scan dispatched %d job(s) for %s",
                    len(queued), connection.get("id"),
                )
            except ValueError as exc:
                logger.warning("Scheduled source scan skipped for %s: %s", connection.get("id"), exc)
            except Exception:
                logger.exception("Scheduled source scan failed: %s", connection.get("id"))

        threading.Thread(target=_run, daemon=True, name="source-scan").start()

    def _tick_scheduled_reports(self, now: datetime) -> None:
        try:
            from src.reports.runner import run_due_schedules
            # Scheduled-report times are entered and displayed in UTC (the panel
            # labels the field "Time (UTC)"), so match against UTC regardless of
            # the host's local zone. A naive local `now` is read as local and
            # converted; an already-aware `now` is normalised to UTC.
            count = run_due_schedules(now=now.astimezone(timezone.utc))
            if count:
                logger.info("Scheduled reports: ran %d schedule(s)", count)
        except Exception:
            logger.exception("Scheduled reports tick failed")

    def _take_posture_snapshots(self) -> None:
        """Run the asset-scoped daily snapshot job once."""
        try:
            from src.posture.service import compute_and_store_daily_snapshots
            count = compute_and_store_daily_snapshots()
            logger.info("Posture snapshots written for %d assets", count)
        except Exception:
            logger.exception("Failed to write posture snapshots")

    def _trigger_kev_refresh(self) -> None:
        import threading

        def _run() -> None:
            try:
                from src.jobs.kev_refresh import refresh_kev_catalog
                result = refresh_kev_catalog()
                logger.info("KEV refresh complete: %s", result)
            except Exception:
                logger.exception("KEV refresh failed")

        threading.Thread(target=_run, daemon=True, name="kev-refresh").start()

    def _trigger_epss_refresh(self) -> None:
        import threading

        def _run() -> None:
            try:
                from src.jobs.epss_refresh import refresh_epss_scores
                result = refresh_epss_scores()
                logger.info("EPSS refresh complete: %s", result)
            except Exception:
                logger.exception("EPSS refresh failed")

        threading.Thread(target=_run, daemon=True, name="epss-refresh").start()

    def _trigger_osv_refresh(self) -> None:
        """Run the OSV mirror refresh + reconcile in a daemon thread.

        Matches _trigger_kev_refresh's shape so threading + lifecycle
        behaviour is identical.
        """
        import threading

        def _run() -> None:
            try:
                from src.jobs.osv_refresh import refresh_osv_catalog
                result = refresh_osv_catalog()
                logger.info("OSV refresh complete: %s", result)
            except Exception:
                logger.exception("OSV refresh failed")

        threading.Thread(target=_run, daemon=True, name="osv-refresh").start()

    def _trigger_sla_recompute(self, asset_ids: list[str]) -> None:
        import threading

        if not asset_ids:
            return

        def _run() -> None:
            try:
                from src.jobs.sla_recompute import trigger_sla_recompute
                trigger_sla_recompute(asset_ids)
            except Exception:
                logger.exception("SLA recompute failed")

        threading.Thread(target=_run, daemon=True, name="sla-recompute").start()

    def _trigger_scanner_coverage_recompute(self, asset_ids: list[str]) -> None:
        import threading

        if not asset_ids:
            return

        def _run() -> None:
            try:
                from src.jobs.scanner_coverage_recompute import (
                    trigger_scanner_coverage_recompute,
                )
                trigger_scanner_coverage_recompute(asset_ids)
            except Exception:
                logger.exception("Scanner-coverage recompute failed")

        threading.Thread(
            target=_run, daemon=True, name="scanner-coverage-recompute"
        ).start()

    def _trigger_data_retention_recompute(self, asset_ids: list[str]) -> None:
        import threading

        if not asset_ids:
            return

        def _run() -> None:
            try:
                from src.jobs.data_retention_recompute import (
                    trigger_data_retention_recompute,
                )
                trigger_data_retention_recompute(asset_ids)
            except Exception:
                logger.exception("Data-retention recompute failed")

        threading.Thread(
            target=_run, daemon=True, name="data-retention-recompute"
        ).start()


_scheduler = AutoRerunScheduler()


def get_scheduler() -> AutoRerunScheduler:
    return _scheduler

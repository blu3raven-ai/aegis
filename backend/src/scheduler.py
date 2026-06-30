from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import datetime
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


def _resolve_orgs(all_orgs: list[str]) -> list[str]:
    return all_orgs


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
        from src.shared.config import read_app_config

        config = read_app_config()
        now = datetime.now()

        tools = config.get("tools") if isinstance(config, dict) else {}
        if not isinstance(tools, dict):
            return

        from src.shared.config import get_orgs_from_source_connections
        all_orgs = get_orgs_from_source_connections()

        dependencies = tools.get("dependencies_scanning") if isinstance(tools.get("dependencies_scanning"), dict) else {}
        if dependencies and dependencies.get("autoRerunEnabled") and _matches_schedule(
            dependencies.get("rerunScheduleType", "simple"),
            dependencies.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_dependencies(dependencies, all_orgs)

        container_scanning = tools.get("container_scanning") if isinstance(tools.get("container_scanning"), dict) else {}
        if container_scanning and container_scanning.get("autoRerunEnabled") and _matches_schedule(
            container_scanning.get("rerunScheduleType", "simple"),
            container_scanning.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_container_scanning(container_scanning, all_orgs)

        secrets = tools.get("secret_scanning") if isinstance(tools.get("secret_scanning"), dict) else {}
        if secrets and secrets.get("autoRerunEnabled") and _matches_schedule(
            secrets.get("rerunScheduleType", "simple"),
            secrets.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_secrets(secrets, all_orgs)

        code_scanning = tools.get("code_scanning") if isinstance(tools.get("code_scanning"), dict) else {}
        if code_scanning and code_scanning.get("autoRerunEnabled") and _matches_schedule(
            code_scanning.get("rerunScheduleType", "simple"),
            code_scanning.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_code_scanning(code_scanning, all_orgs)

        iac_scanning = tools.get("iac_scanning") if isinstance(tools.get("iac_scanning"), dict) else {}
        if iac_scanning and iac_scanning.get("autoRerunEnabled") and _matches_schedule(
            iac_scanning.get("rerunScheduleType", "simple"),
            iac_scanning.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_iac_scanning(iac_scanning, all_orgs)

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
            count = run_due_schedules(now=now)
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

    def _trigger_dependencies(self, dependencies_config: dict[str, Any], all_orgs: list[str]) -> None:
        import threading
        from src.shared.config import (
            get_token_for_org, get_dependencies_scanner_config,
            get_source_type_for_org, org_has_source_connections,
        )
        from src.dependencies.scanner import execute_dependencies_scan_once
        from src.dependencies.scanner import _dependencies_runtime
        from src.storage import create_dependencies_run

        orgs = _resolve_orgs(all_orgs)
        if not orgs:
            logger.warning("Dependencies auto-rerun: no orgs configured, skipping")
            return

        scanner_config = get_dependencies_scanner_config()
        for org in orgs:
            if not org_has_source_connections(org, categories=["code-repositories"]):
                logger.warning("Dependencies auto-rerun: no code-repository connections for %s, skipping", org)
                continue
            if _dependencies_runtime.probe(org)["active"]:
                logger.info("Dependencies auto-rerun: scan already running for %s, skipping", org)
                continue
            source_type = get_source_type_for_org(org, "code-repositories")
            token = get_token_for_org(org) or ""
            run_id = f"auto-{int(time.time() * 1000)}"
            create_dependencies_run(org, run_id)
            logger.info("Dependencies auto-rerun triggered for %s (run %s)", org, run_id)
            thread = threading.Thread(
                target=execute_dependencies_scan_once,
                args=(org, token, run_id),
                kwargs={"source_type": source_type, "scanner_config": scanner_config, "mode": "incremental", "runtime": _dependencies_runtime},
                daemon=True,
            )
            thread.start()

    def _trigger_container_scanning(self, ct_config: dict[str, Any], all_orgs: list[str]) -> None:
        import threading
        from src.shared.config import (
            get_token_for_org, get_container_scanner_config,
            get_source_type_for_org, org_has_source_connections,
        )
        from src.containers.scanner import execute_container_scan_once
        from src.containers.scanner import _container_scanning_runtime
        from src.storage import create_container_scanning_run

        orgs = _resolve_orgs(all_orgs)
        if not orgs:
            logger.warning("Container scanning auto-rerun: no orgs configured, skipping")
            return

        scanner_config = get_container_scanner_config()
        for org in orgs:
            if not org_has_source_connections(org, categories=["container-images"]):
                logger.warning("Container scanning auto-rerun: no container-image connections for %s, skipping", org)
                continue
            if _container_scanning_runtime.probe(org)["active"]:
                logger.info("Container scanning auto-rerun: scan already running for %s, skipping", org)
                continue
            source_type = get_source_type_for_org(org, "container-images")
            token = get_token_for_org(org) or ""
            run_id = f"auto-{int(time.time() * 1000)}"
            create_container_scanning_run(org, run_id)
            logger.info("Container scanning auto-rerun triggered for %s (run %s)", org, run_id)
            thread = threading.Thread(
                target=execute_container_scan_once,
                args=(org, token, run_id),
                kwargs={"source_type": source_type, "scanner_config": scanner_config, "mode": "incremental", "runtime": _container_scanning_runtime},
                daemon=True,
            )
            thread.start()

    def _trigger_secrets(self, secrets_config: dict[str, Any], all_orgs: list[str]) -> None:
        import threading
        from src.shared.config import get_source_type_for_org
        from src.secrets.service_runs import start_secret_runs
        from src.secrets.scanner import execute_secret_scan_once

        orgs = _resolve_orgs(all_orgs)
        if not orgs:
            logger.warning("Secrets auto-rerun: no orgs configured, skipping")
            return

        def _launch(org, run_id, token, runtime, scanner_config, scan_depth):
            # Resolve the source type per org so ingest can attach findings to
            # assets. Poll in a daemon thread so a long scan can't block the tick.
            source_type = get_source_type_for_org(org, "code-repositories")
            threading.Thread(
                target=execute_secret_scan_once,
                args=(org, token, run_id),
                kwargs={"source_type": source_type, "scanner_config": scanner_config,
                        "runtime": runtime, "scan_depth": scan_depth},
                daemon=True,
            ).start()

        logger.info("Secrets auto-rerun triggered for orgs: %s", orgs)
        start_secret_runs(orgs, run_launcher=_launch)

    def _trigger_code_scanning(self, code_scanning_config: dict[str, Any], all_orgs: list[str]) -> None:
        import threading
        from src.shared.config import (
            get_token_for_org, get_code_scanning_scanner_config,
            get_source_type_for_org, org_has_source_connections,
        )
        from src.code_scanning.scanner import execute_code_scanning_scan_once
        from src.code_scanning.scanner import _code_scanning_runtime
        from src.storage import create_code_scanning_run

        orgs = _resolve_orgs(all_orgs)
        if not orgs:
            logger.warning("Code scanning auto-rerun: no orgs configured, skipping")
            return

        scanner_config = get_code_scanning_scanner_config()
        for org in orgs:
            if not org_has_source_connections(org, categories=["code-repositories"]):
                logger.warning("Code scanning auto-rerun: no source connections for %s, skipping", org)
                continue
            if _code_scanning_runtime.probe(org)["active"]:
                logger.info("Code scanning auto-rerun: scan already running for %s, skipping", org)
                continue
            source_type = get_source_type_for_org(org, "code-repositories")
            token = get_token_for_org(org) or ""
            run_id = f"auto-{int(time.time() * 1000)}"
            create_code_scanning_run(org, run_id)
            logger.info("Code scanning auto-rerun triggered for %s (run %s)", org, run_id)
            thread = threading.Thread(
                target=execute_code_scanning_scan_once,
                args=(org, token, run_id),
                kwargs={"source_type": source_type, "scanner_config": scanner_config, "runtime": _code_scanning_runtime},
                daemon=True,
            )
            thread.start()

    def _trigger_iac_scanning(self, iac_config: dict[str, Any], all_orgs: list[str]) -> None:
        import threading
        from src.shared.config import (
            get_token_for_org, get_source_type_for_org, org_has_source_connections,
        )
        from src.iac.scanner import execute_iac_scan_once, _iac_runtime
        from src.storage import create_iac_run

        orgs = _resolve_orgs(all_orgs)
        if not orgs:
            logger.warning("IaC scanning auto-rerun: no orgs configured, skipping")
            return

        for org in orgs:
            if not org_has_source_connections(org, categories=["code-repositories"]):
                logger.warning("IaC scanning auto-rerun: no source connections for %s, skipping", org)
                continue
            if _iac_runtime.probe(org)["active"]:
                logger.info("IaC scanning auto-rerun: scan already running for %s, skipping", org)
                continue
            source_type = get_source_type_for_org(org, "code-repositories")
            token = get_token_for_org(org) or ""
            run_id = f"auto-{int(time.time() * 1000)}"
            create_iac_run(org, run_id)
            logger.info("IaC scanning auto-rerun triggered for %s (run %s)", org, run_id)
            thread = threading.Thread(
                target=execute_iac_scan_once,
                args=(org, token, run_id),
                kwargs={"source_type": source_type, "runtime": _iac_runtime},
                daemon=True,
            )
            thread.start()


_scheduler = AutoRerunScheduler()


def get_scheduler() -> AutoRerunScheduler:
    return _scheduler

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

        dependencies = tools.get("dependencies") if isinstance(tools.get("dependencies"), dict) else {}
        if dependencies and dependencies.get("autoRerunEnabled") and _matches_schedule(
            dependencies.get("rerunScheduleType", "simple"),
            dependencies.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_dependencies(dependencies, all_orgs)

        container_scanning = tools.get("containerScanning") if isinstance(tools.get("containerScanning"), dict) else {}
        if container_scanning and container_scanning.get("autoRerunEnabled") and _matches_schedule(
            container_scanning.get("rerunScheduleType", "simple"),
            container_scanning.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_container_scanning(container_scanning, all_orgs)

        secrets = tools.get("secrets") if isinstance(tools.get("secrets"), dict) else {}
        if secrets and secrets.get("autoRerunEnabled") and _matches_schedule(
            secrets.get("rerunScheduleType", "simple"),
            secrets.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_secrets(secrets, all_orgs)

        code_scanning = tools.get("codeScanning") if isinstance(tools.get("codeScanning"), dict) else {}
        if code_scanning and code_scanning.get("autoRerunEnabled") and _matches_schedule(
            code_scanning.get("rerunScheduleType", "simple"),
            code_scanning.get("rerunScheduleValue", "02:00"),
            now,
        ):
            self._trigger_code_scanning(code_scanning, all_orgs)

        # Midnight UTC: write daily posture snapshots
        if now.hour == 0 and now.minute == 0:
            self._take_posture_snapshots(all_orgs)

    def _take_posture_snapshots(self, all_orgs: list[str]) -> None:
        import threading

        def _run_for_org(org: str) -> None:
            try:
                from src.posture.service import get_posture_snapshot, upsert_posture_snapshot
                payload = get_posture_snapshot(org=org)
                upsert_posture_snapshot(org=org, payload=payload)
                logger.info("Posture snapshot written for org %s", org)
            except Exception:
                logger.exception("Failed to write posture snapshot for org %s", org)

        for org in all_orgs:
            threading.Thread(
                target=_run_for_org,
                args=(org,),
                daemon=True,
                name=f"posture-snapshot-{org}",
            ).start()

    def _trigger_dependencies(self, dependencies_config: dict[str, Any], all_orgs: list[str]) -> None:
        import threading
        from src.shared.config import (
            get_token_for_org, get_dependencies_scanner_config,
            get_source_type_for_org, org_has_source_connections,
        )
        from src.dependencies.scanner import execute_dependencies_scan_once
        from src.dependencies.router import _dependencies_runtime
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
        from src.containers.router import _container_scanning_runtime
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
        from src.secrets.service_runs import start_secret_runs

        orgs = _resolve_orgs(all_orgs)
        if not orgs:
            logger.warning("Secrets auto-rerun: no orgs configured, skipping")
            return

        logger.info("Secrets auto-rerun triggered for orgs: %s", orgs)
        start_secret_runs(orgs)

    def _trigger_code_scanning(self, code_scanning_config: dict[str, Any], all_orgs: list[str]) -> None:
        import threading
        from src.shared.config import (
            get_token_for_org, get_code_scanning_scanner_config,
            get_source_type_for_org, org_has_source_connections,
        )
        from src.code_scanning.scanner import execute_code_scanning_scan_once
        from src.code_scanning.router import _code_scanning_runtime
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


_scheduler = AutoRerunScheduler()


def get_scheduler() -> AutoRerunScheduler:
    return _scheduler

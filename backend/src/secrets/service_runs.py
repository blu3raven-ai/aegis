from __future__ import annotations

import random
import time
from typing import Any, Callable

from src.secrets.scanner import InMemoryScanRuntime
from src.shared.config import (
    get_token_for_org,
    get_secret_scanner_config,
    org_has_source_connections,
)
from src.shared.paths import parse_org_values
from src.storage import create_secret_run, list_secret_runs

ACTIVE_STATUSES = {"queued", "running", "ingesting"}

_scan_runtime: InMemoryScanRuntime | None = None


def get_runtime() -> InMemoryScanRuntime:
    global _scan_runtime
    if _scan_runtime is None:
        _scan_runtime = InMemoryScanRuntime()
    return _scan_runtime


def latest_run_for_org(org: str) -> dict[str, Any] | None:
    runs = list_secret_runs(org)
    return runs[0] if runs else None


def start_secret_runs(
    orgs: list[str],
    scan_depth: str | None = None,
    runtime_getter: Callable[[], InMemoryScanRuntime] = get_runtime,
    run_launcher: Callable[
        [str, str, str, InMemoryScanRuntime, dict[str, str], str | None],
        None,
    ] | None = None,
    get_token_for_org: Callable[[str], str | None] = get_token_for_org,
    get_scanner_config: Callable[[], dict[str, str]] = get_secret_scanner_config,
) -> tuple[dict[str, Any], int]:
    parsed_orgs = parse_org_values(orgs)

    missing_connection_orgs: list[str] = []
    for org_name in parsed_orgs:
        if not org_has_source_connections(org_name, categories=["code-repositories"]):
            missing_connection_orgs.append(org_name)

    if missing_connection_orgs:
        return {"error": f"No source connections configured for: {', '.join(missing_connection_orgs)}. Add connections in Settings > Sources."}, 503

    runtime = runtime_getter()
    active_orgs: list[str] = []
    for org_name in parsed_orgs:
        latest = latest_run_for_org(org_name)
        if latest and latest.get("status") in ACTIVE_STATUSES:
            active_orgs.append(org_name)
        elif runtime.probe(org_name).get("active"):
            active_orgs.append(org_name)

    if active_orgs:
        return {"error": f"Secret scan already running for: {', '.join(active_orgs)}"}, 409

    scanner_config = get_scanner_config()
    started_runs: list[dict[str, str]] = []
    for org_name in parsed_orgs:
        run_id = f"{int(time.time() * 1000)}-{random.randint(1000, 9999)}"
        create_secret_run(org_name, run_id)
        started_runs.append({"org": org_name, "runId": run_id})
        fallback_token = get_token_for_org(org_name) or ""
        if run_launcher:
            run_launcher(org_name, run_id, fallback_token, runtime, scanner_config, scan_depth)

    return {
        "runs": started_runs,
        "message": f"Started {len(started_runs)} secret scan(s) across {len(parsed_orgs)} organization(s)",
    }, 202

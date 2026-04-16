from __future__ import annotations

import random
import time
from typing import Any, Callable

from src.secrets.scanner import (
    InMemoryScanRuntime,
    mark_run_cancelled,
    reconcile_expected_repos,
)
from src.shared.config import (
    get_github_token_for_org,
    get_secret_scanner_config,
    org_has_source_connections,
)
from src.shared.event_bus import Event, get_event_bus
from src.shared.paths import parse_org_values
from src.storage import create_secret_run, list_secret_runs

ACTIVE_STATUSES = {"queued", "running", "ingesting"}

_scan_runtime: InMemoryScanRuntime | None = None


def get_runtime() -> InMemoryScanRuntime:
    global _scan_runtime
    if _scan_runtime is None:
        _scan_runtime = InMemoryScanRuntime()
    return _scan_runtime


def combined_status(runs: list[dict[str, Any]]) -> str:
    for status in ["running", "ingesting", "queued", "failed", "cancelled"]:
        if any(run.get("status") == status for run in runs):
            return status
    return "completed"


def combine_latest_runs(orgs: list[str], runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not runs:
        return None
    if len(runs) == 1:
        return runs[0]

    active_runs = [run for run in runs if run.get("status") in ACTIVE_STATUSES]
    source_runs = active_runs or runs
    current = source_runs[0]
    status = combined_status(source_runs)
    expected = sum(((run.get("progress") or {}).get("expectedRepos") or 0) for run in source_runs)
    scanned = sum(((run.get("progress") or {}).get("scannedRepos") or 0) for run in source_runs)
    finished = sum(((run.get("progress") or {}).get("finishedRepos") or 0) for run in source_runs)
    expected = reconcile_expected_repos(expected, scanned, finished) or 0
    progress_values = [((run.get("progress") or {}).get("percent") or 0) for run in source_runs]
    percent = min(100 if status == "completed" else 95, (finished / expected) * (100 if status == "completed" else 94)) if expected else (sum(progress_values) / len(progress_values) if progress_values else 0)
    current_repo_run = next((run for run in source_runs if (run.get("progress") or {}).get("currentRepo")), current)
    current_repo = (current_repo_run.get("progress") or {}).get("currentRepo")

    merged = dict(current)
    merged.update(
        {
            "id": "+".join(str(run.get("id", "")) for run in source_runs),
            "organization": ", ".join(orgs),
            "status": status,
            "findingsCount": sum((run.get("findingsCount") or 0) for run in source_runs),
            "error": " | ".join(f"{run.get('organization')}: {run.get('error')}" for run in source_runs if run.get("error")) or None,
            "logTail": [line for run in source_runs for line in (run.get("logTail") or [])[-3:]][-8:],
            "progress": {
                "expectedRepos": expected or None,
                "scannedRepos": scanned,
                "finishedRepos": finished,
                "percent": percent,
                "currentRepo": f"{current_repo_run.get('organization')}/{current_repo}" if current_repo else None,
                "stage": "scanning" if status == "running" else status,
            },
        }
    )
    return merged


def latest_run_for_org(org: str) -> dict[str, Any] | None:
    runs = list_secret_runs(org)
    return runs[0] if runs else None


def list_runs_payload(orgs: list[str]) -> dict[str, Any]:
    latest_by_org = []
    all_completed: list[dict[str, Any]] = []
    for org_name in orgs:
        runs = list_secret_runs(org_name)
        latest_by_org.append({"org": org_name, "run": runs[0] if runs else None})
        for run in runs:
            if run.get("status") == "completed" and run.get("finishedAt"):
                all_completed.append(run)
    latest_runs = [entry["run"] for entry in latest_by_org if entry["run"]]
    latest = combine_latest_runs(orgs, latest_runs)
    runs = sorted(latest_runs, key=lambda run: run.get("createdAt") or "", reverse=True)
    active_orgs = [
        {"org": entry["org"], "active": bool(entry["run"] and entry["run"].get("status") in ACTIVE_STATUSES), "runId": (entry["run"] or {}).get("id")}
        for entry in latest_by_org
    ]
    last_completed = max(all_completed, key=lambda r: r.get("finishedAt") or "", default=None)
    return {
        "latest": latest,
        "runs": runs[:20],
        "lastCompleted": last_completed,
        "multiOrgStatus": {"orgs": active_orgs, "anyActive": any(item["active"] for item in active_orgs), "totalOrgs": len(orgs)},
    }


def latest_run_payload(org: str) -> dict[str, Any]:
    return {"run": latest_run_for_org(org)}


def start_secret_runs(
    orgs: list[str],
    scan_depth: str | None = None,
    runtime_getter: Callable[[], InMemoryScanRuntime] = get_runtime,
    run_launcher: Callable[
        [str, str, str, InMemoryScanRuntime, dict[str, str], str | None],
        None,
    ] | None = None,
    get_token_for_org: Callable[[str], str | None] = get_github_token_for_org,
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


def cancel_secret_runs(
    orgs: list[str],
    runtime_getter: Callable[[], InMemoryScanRuntime] = get_runtime,
) -> tuple[dict[str, Any], int]:
    runtime = runtime_getter()
    parsed_orgs = parse_org_values(orgs)

    active_before: set[str] = set()
    for org_name in parsed_orgs:
        latest = latest_run_for_org(org_name)
        if (latest and latest.get("status") in ACTIVE_STATUSES) or runtime.probe(org_name).get("active"):
            active_before.add(org_name)

    results: list[dict[str, Any]] = []

    for org_name in parsed_orgs:
        result: dict[str, Any] = {"org": org_name, "cancelled": False}

        from src.runner.jobs import cancel_jobs_for_org
        cancel_jobs_for_org(org_name, job_type="secrets")

        cancel_result = runtime.cancel(org_name)

        if cancel_result["ok"]:
            mark_run_cancelled(org_name, cancel_result["runId"])
            result["cancelled"] = True
            result["runId"] = cancel_result["runId"]
            get_event_bus().publish_sync(Event(
                event_type="scan.failed",
                data={"tool": "secrets", "org": org_name, "runId": cancel_result["runId"], "error": "Cancelled by user"},
                org=org_name,
            ))
            latest = latest_run_for_org(org_name)
            if latest:
                result["run"] = latest
        else:
            latest = latest_run_for_org(org_name)
            if latest and latest.get("status") in ACTIVE_STATUSES:
                cancelled_run = mark_run_cancelled(org_name, latest["id"])
                result["cancelled"] = True
                result["runId"] = latest["id"]
                result["run"] = cancelled_run or latest
                get_event_bus().publish_sync(Event(
                    event_type="scan.failed",
                    data={"tool": "secrets", "org": org_name, "runId": latest["id"], "error": "Cancelled by user"},
                    org=org_name,
                ))
            else:
                result["error"] = (
                    "Cancellation did not finish for this organization."
                    if org_name in active_before
                    else "No active secret scan"
                )
        results.append(result)

    still_active = []
    for org_name in parsed_orgs:
        if org_name not in active_before:
            continue
        latest = latest_run_for_org(org_name)
        if (latest and latest.get("status") in ACTIVE_STATUSES) or runtime.probe(org_name).get("active"):
            still_active.append(org_name)

    if still_active:
        return {
            "error": f"Cancellation still in progress for: {', '.join(still_active)}. Wait a moment and try again."
        }, 409

    if results and all(not result["cancelled"] for result in results):
        first_error = next((result.get("error") for result in results if result.get("error")), None)
        return {"error": first_error or "No active secret scans to cancel."}, 409

    cancelled_count = sum(1 for result in results if result["cancelled"])
    active_count = len(active_before) or len(parsed_orgs)
    return {
        "ok": cancelled_count > 0 and (not active_before or cancelled_count == len(active_before)),
        "results": results,
        "message": f"Cancelled {cancelled_count} of {active_count} active org scan(s)",
    }, 200

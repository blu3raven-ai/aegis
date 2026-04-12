"""Shared multi-org scan orchestration — start and cancel logic.

Used by SCA, SAST, and Container scanning routers. Each tool provides
its own runtime, execution function, and run CRUD callbacks.
"""
from __future__ import annotations

import random
import threading
import time
from typing import Any, Callable

from src.shared.config import get_github_token_for_org, org_has_source_connections
from src.shared.event_bus import Event, get_event_bus
from src.shared.paths import now_iso


def _generate_run_id() -> str:
    return f"{int(time.time() * 1000)}-{random.randint(1000, 9999)}"


def start_multi_org_scan(
    orgs: list[str],
    runtime: Any,
    create_run_fn: Callable[[str, str], Any],
    execute_fn: Callable[..., None],
    execute_kwargs: dict[str, Any],
    source_category: str,
    on_org_complete: Callable[[str], None] | None = None,
    tool_label: str = "",
    update_run_fn: Callable[[str, str, dict[str, Any]], None] | None = None,
    skip_connection_check: bool = False,
) -> tuple[dict[str, Any], int]:
    """Start scans across multiple orgs sequentially in a background thread.

    Args:
        orgs: List of organization names to scan.
        runtime: Tool's InMemoryScanRuntime instance (must have .probe() and .is_cancelled()).
        create_run_fn: Creates a run record — called as create_run_fn(org, run_id).
        execute_fn: Executes the scan — called as execute_fn(org, token, run_id, **execute_kwargs, runtime=runtime).
        execute_kwargs: Tool-specific kwargs passed to execute_fn (scanner_config, mode, etc.).
        source_category: Connection category to check ("code-repositories" or "container-images").
        on_org_complete: Called after each org completes (e.g., cache invalidation).
        tool_label: Human-readable label for error messages ("dependency", "container", "SAST").
        update_run_fn: Updates a run record — needed for marking cancelled runs. Called as update_run_fn(org, run_id, patch).
        skip_connection_check: Skip source connection validation (e.g., SCA advisories_only mode).

    Returns:
        Tuple of (response_dict, http_status_code).
    """
    org_queue: list[tuple[str, str]] = []

    for org_name in orgs:
        if not skip_connection_check and not org_has_source_connections(org_name, categories=[source_category]):
            return {"error": f"No source connections configured for {org_name}. Add connections in Settings > Sources."}, 503

        if runtime.probe(org_name)["active"]:
            return {"error": f"{tool_label} scan already running for {org_name}"}, 409

        token = get_github_token_for_org(org_name) or ""
        org_queue.append((org_name, token))

    if not org_queue:
        return {"runs": [], "message": "No organizations to scan"}, 200

    captured_queue = list(org_queue)
    first_org, _ = captured_queue[0]
    first_run_id = _generate_run_id()
    create_run_fn(first_org, first_run_id)

    def run_sequentially() -> None:
        for i, (org_name, token) in enumerate(captured_queue):
            if i == 0:
                run_id = first_run_id
            else:
                if runtime.is_cancelled(first_run_id):
                    break
                run_id = _generate_run_id()
                create_run_fn(org_name, run_id)

            execute_fn(org_name, token, run_id, **execute_kwargs, runtime=runtime)
            if on_org_complete:
                on_org_complete(org_name)

            if runtime.is_cancelled(run_id):
                # Cancel all remaining queued orgs
                if update_run_fn:
                    for rem_org, _ in captured_queue[i + 1:]:
                        rem_run_id = _generate_run_id()
                        create_run_fn(rem_org, rem_run_id)
                        update_run_fn(rem_org, rem_run_id, {
                            "status": "cancelled",
                            "finishedAt": now_iso(),
                            "error": "Cancelled by user",
                        })
                break

    threading.Thread(target=run_sequentially, daemon=True).start()

    return {
        "runs": [{"org": o, "queued": True} for o, _ in org_queue],
        "message": f"Started {len(org_queue)} {tool_label} scan(s)",
    }, 202


def cancel_multi_org_scan(
    orgs: list[str],
    runtime: Any,
    update_run_fn: Callable[[str, str, dict[str, Any]], None],
    job_type: str,
) -> dict[str, Any]:
    """Cancel active scans across multiple orgs.

    Args:
        orgs: List of organization names.
        runtime: Tool's InMemoryScanRuntime instance (must have .cancel()).
        update_run_fn: Updates a run record — called as update_run_fn(org, run_id, patch).
        job_type: Runner job type string ("dependencies", "code_scanning", "container_scanning").

    Returns:
        Response dict with ok status and per-org results.
    """
    from src.runner.jobs import cancel_jobs_for_org

    results: list[dict[str, Any]] = []
    for org_name in orgs:
        cancel_jobs_for_org(org_name, job_type=job_type)

        result = runtime.cancel(org_name)
        cancelled = result.get("ok", False)
        if cancelled and result.get("runId"):
            update_run_fn(org_name, result["runId"], {
                "status": "cancelled",
                "finishedAt": now_iso(),
                "error": "Cancelled by user",
            })
            get_event_bus().publish_sync(Event(
                event_type="scan.failed",
                data={"tool": job_type, "org": org_name, "runId": result["runId"], "error": "Cancelled by user"},
                org=org_name,
            ))
        results.append({"org": org_name, "cancelled": True})

    return {"ok": True, "results": results}

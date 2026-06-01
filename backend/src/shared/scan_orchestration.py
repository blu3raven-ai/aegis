"""Shared multi-org scan orchestration — start and cancel logic.

Used by SCA, SAST, and Container scanning routers. Each tool provides
its own runtime, execution function, and run CRUD callbacks.
"""
from __future__ import annotations

import os
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from src.shared.config import get_github_token_for_org, org_has_source_connections
from src.shared.event_bus import Event, get_event_bus
from src.shared.event_emit_helpers import emit_scan_completed, emit_scan_failed, emit_scan_started
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

    def _run_one_org(org_name: str, token: str, run_id: str) -> None:
        """Execute one org's scan and emit lifecycle events.

        Failures are caught and emitted as scan.failed so they never propagate
        to sibling workers running concurrently.
        """
        emit_scan_started(
            org_id=org_name,
            scan_id=run_id,
            repo_id=None,
            scanner_type=tool_label,
            trigger_event_id=str(uuid.uuid4()),
        )
        scan_start_ts = time.time()
        try:
            result = execute_fn(org_name, token, run_id, **execute_kwargs, runtime=runtime)
        except Exception as exc:
            emit_scan_failed(
                org_id=org_name,
                scan_id=run_id,
                error=str(exc),
                retryable=False,
            )
            return
        duration_ms = int((time.time() - scan_start_ts) * 1000)
        if result is None:
            emit_scan_failed(
                org_id=org_name,
                scan_id=run_id,
                error="scan returned no result",
                retryable=False,
            )
        else:
            emit_scan_completed(
                org_id=org_name,
                scan_id=run_id,
                duration_ms=duration_ms,
                findings_count=0,
            )
        if on_org_complete:
            on_org_complete(org_name)

    def run_concurrently() -> None:
        # Pre-assign run IDs so the response is consistent with what callers
        # already received in the 202 body (run IDs are embedded in the queue).
        org_runs: list[tuple[str, str, str]] = []
        for i, (org_name, token) in enumerate(captured_queue):
            run_id = first_run_id if i == 0 else _generate_run_id()
            if i > 0:
                create_run_fn(org_name, run_id)
            org_runs.append((org_name, token, run_id))

        max_workers = min(len(org_runs), int(os.getenv("MULTI_ORG_CONCURRENCY", "8")))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_run_one_org, org_name, token, run_id): (org_name, run_id)
                for org_name, token, run_id in org_runs
                # Respect a pre-flight cancellation; already-running workers are
                # not interrupted (cancellation on running futures is a no-op).
                if not runtime.is_cancelled(first_run_id)
            }
            for future in futures:
                org_name, run_id = futures[future]
                try:
                    future.result()
                except Exception:
                    # Exceptions are already handled inside _run_one_org;
                    # this is a safety net that keeps the pool draining.
                    pass

        # Mark any orgs that were skipped due to a pre-flight cancellation.
        if update_run_fn:
            submitted_orgs = {org for org, run_id in futures.values()}
            for org_name, _, run_id in org_runs:
                if org_name not in submitted_orgs:
                    update_run_fn(org_name, run_id, {
                        "status": "cancelled",
                        "finishedAt": now_iso(),
                        "error": "Cancelled by user",
                    })

    threading.Thread(target=run_concurrently, daemon=True).start()

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

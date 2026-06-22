"""Legacy module-level job queue API.

Kept as a thin backward-compat shim for existing call sites.  New code should
depend on the ``JobQueue`` Protocol via ``src.runner.queue`` and obtain a
concrete queue from ``src.runner.queue.factory.get_queue()``.

``read_job`` and ``SENSITIVE_KEYS`` are re-exported here because several call
sites import them from this module.  They originate in ``src.runner.storage``
and ``src.runner.queue.file_backed`` respectively but are stable API surface
as long as this shim exists.

Will be removed once all call sites migrate (Phase 1+).

.. deprecated::
    Import from ``src.runner.queue`` instead.
"""
from __future__ import annotations

import secrets
import threading
from datetime import datetime, timezone
from typing import Any

from src.runner.encryption import SENSITIVE_KEYS as _SENSITIVE_KEYS, encrypt_env_vars, decrypt_env_vars
from src.runner.storage import list_jobs, read_job, read_runner, write_job, write_runner
from src.shared.paths import now_iso

# Explicit re-export so ``from src.runner.jobs import read_job`` keeps working.
__all__ = [
    "SENSITIVE_KEYS",
    "STALE_JOB_SECONDS",
    "assign_next_job",
    "cancel_jobs_for_org",
    "cancel_jobs_for_scans",
    "cancel_stale_jobs",
    "complete_job",
    "create_job",
    "fail_job",
    "read_job",
    "requeue_stale_jobs",
    "update_job_progress",
    "update_job_status",
]


_assign_lock = threading.Lock()

STALE_JOB_SECONDS = 120

SENSITIVE_KEYS = _SENSITIVE_KEYS

# Cipher helpers delegated to src.runner.encryption so all queue backends
# share one implementation and wire-compatible encrypted values.
_encrypt_env_vars = encrypt_env_vars
_decrypt_env_vars = decrypt_env_vars


# _inner helpers — called by both module-level API and PostgresBackedQueue

def _create_job_inner(
    *,
    job_type: str,
    org: str,
    run_id: str,
    env_vars: dict[str, str],
    expected_repo_count: int | None = None,
) -> str:
    job_id = f"job-{secrets.token_hex(8)}"
    if expected_repo_count is not None:
        env_vars["EXPECTED_REPO_COUNT"] = str(expected_repo_count)
    job: dict[str, Any] = {
        "id": job_id,
        "jobType": job_type,
        "org": org,
        "runId": run_id,
        "status": "queued",
        "runnerId": None,
        "createdAt": now_iso(),
        "completedAt": None,
        "envVars": _encrypt_env_vars(env_vars),
    }
    write_job(job)
    return job_id


def _assign_next_job_inner(*, runner_id: str) -> dict[str, Any] | None:
    with _assign_lock:
        queued = list_jobs(status="queued")
        if not queued:
            return None
        job = queued[0]
        job["status"] = "assigned"
        job["runnerId"] = runner_id
        job["startedAt"] = now_iso()
        write_job(job)

    # Decrypt sensitive env vars for runner
    if job and job.get("envVars"):
        job["envVars"] = _decrypt_env_vars(job["envVars"])
    return job


def _update_job_status_inner(job_id: str, status: str, **kwargs: Any) -> dict[str, Any] | None:
    job = read_job(job_id)
    if not job:
        return None
    job["status"] = status
    if status in ("completed", "failed"):
        job["completedAt"] = now_iso()
    for key, value in kwargs.items():
        job[key] = value
    write_job(job)
    return job


def _complete_job_inner(job_id: str, *, result: dict[str, Any] | None = None) -> dict[str, Any] | None:
    job = _update_job_status_inner(job_id, "completed")
    if job and job.get("runnerId"):
        runner = read_runner(job["runnerId"])
        if runner:
            runner["jobsCompleted"] = runner.get("jobsCompleted", 0) + 1
            write_runner(runner)
    return job


def _fail_job_inner(job_id: str, *, error: str, retryable: bool = False) -> dict[str, Any] | None:
    status = "queued" if retryable else "failed"
    return _update_job_status_inner(job_id, status, error=error)


def _read_job_inner(job_id: str) -> dict[str, Any] | None:
    job = read_job(job_id)
    if job and job.get("envVars"):
        job["envVars"] = _decrypt_env_vars(job["envVars"])
    return job


# Module-level public API — preserved for backward compat

def create_job(
    job_type: str,
    org: str,
    run_id: str,
    env_vars: dict[str, str],
    expected_repo_count: int | None = None,
) -> dict[str, Any]:
    """Module-level API — delegates to _inner."""
    job_id = _create_job_inner(
        job_type=job_type, org=org, run_id=run_id,
        env_vars=env_vars,
        expected_repo_count=expected_repo_count,
    )
    # Callers expect the full job dict back, not just the ID.
    return read_job(job_id) or {"id": job_id}


def assign_next_job(runner_id: str) -> dict[str, Any] | None:
    """Module-level API — preserved for backward compat. Delegates to _inner."""
    return _assign_next_job_inner(runner_id=runner_id)


def update_job_status(job_id: str, status: str, **kwargs: Any) -> dict[str, Any] | None:
    """Module-level API — preserved for backward compat. Delegates to _inner."""
    return _update_job_status_inner(job_id, status, **kwargs)


def update_job_progress(job_id: str, log_tail: list[str], progress: dict[str, Any]) -> dict[str, Any] | None:
    """Mark job as running if still assigned. Progress data lives on ScanRun, not RunnerJob."""
    job = read_job(job_id)
    if not job:
        return None
    if job["status"] == "assigned":
        job["status"] = "running"
        write_job(job)
    return job


def complete_job(job_id: str) -> dict[str, Any] | None:
    """Module-level API — preserved for backward compat. Delegates to _inner."""
    return _complete_job_inner(job_id)


def fail_job(job_id: str, error: str) -> dict[str, Any] | None:
    """Module-level API — preserved for backward compat. Delegates to _inner."""
    return _fail_job_inner(job_id, error=error)


def cancel_jobs_for_org(org: str, job_type: str | None = None) -> list[dict[str, Any]]:
    """Cancel active runner jobs for an org. Optionally filter by job_type."""
    cancelled: list[dict[str, Any]] = []
    for job in list_jobs():
        if job.get("org") != org:
            continue
        if job.get("status") not in ("queued", "assigned", "running"):
            continue
        if job_type and job.get("jobType") != job_type:
            continue
        job["status"] = "cancelled"
        job["completedAt"] = now_iso()
        write_job(job)
        cancelled.append(job)
    return cancelled


def cancel_jobs_for_scans(scan_ids: list[str]) -> list[dict[str, Any]]:
    """Cancel active runner jobs whose runId is keyed off any of the given scan IDs.

    Used by the supersede path (cancel_older_queued_for_pr) so that when a newer
    scan replaces older queued ones, the runner stops processing the obsolete
    jobs instead of running them to completion and having the result dropped on
    ingest. The runId pattern is ``f"{scan_id}:{scanner}"`` (see
    scans/service.py::_dispatch_scanner_jobs), so one scan ID maps to one job
    per scanner.

    Runner-side cancellation propagates on the next progress poll:
    runner/router.py::post_progress re-reads the job, sees status=='cancelled',
    and the response sets ``cancelled: true`` so the runner triggers its own
    cancel path.
    """
    if not scan_ids:
        return []
    prefixes = tuple(f"{sid}:" for sid in scan_ids)
    cancelled: list[dict[str, Any]] = []
    for job in list_jobs():
        if job.get("status") not in ("queued", "assigned", "running"):
            continue
        run_id = job.get("runId", "")
        if not run_id.startswith(prefixes):
            continue
        job["status"] = "cancelled"
        job["completedAt"] = now_iso()
        write_job(job)
        cancelled.append(job)
    return cancelled


def cancel_stale_jobs() -> int:
    """Cancel all runner jobs stuck in active states. Called on backend startup."""
    count = 0
    for job in list_jobs():
        if job.get("status") in ("pending", "queued", "assigned", "running"):
            job["status"] = "cancelled"
            job["completedAt"] = now_iso()
            write_job(job)
            count += 1
    return count


def requeue_stale_jobs() -> list[dict[str, Any]]:
    requeued: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    for job in list_jobs():
        if job.get("status") not in ("assigned", "running"):
            continue
        runner_id = job.get("runnerId")
        if not runner_id:
            continue
        runner = read_runner(runner_id)
        if not runner:
            job["status"] = "queued"
            job["runnerId"] = None
            job["startedAt"] = None
            write_job(job)
            requeued.append(job)
            continue
        last_hb = runner.get("lastHeartbeatAt", "")
        if not last_hb:
            continue
        try:
            hb_time = datetime.fromisoformat(last_hb.replace("Z", "+00:00"))
            if (now - hb_time).total_seconds() > STALE_JOB_SECONDS:
                job["status"] = "queued"
                job["runnerId"] = None
                job["startedAt"] = None
                write_job(job)
                requeued.append(job)
        except (ValueError, TypeError):
            pass

    return requeued

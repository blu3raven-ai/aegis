"""Job queue: create, assign, update status/progress, re-queue stale jobs."""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import threading
from datetime import datetime, timezone
from typing import Any

from src.runner.storage import list_jobs, read_job, read_runner, write_job, write_runner
from src.shared.paths import now_iso


_assign_lock = threading.Lock()

STALE_JOB_SECONDS = 120

SENSITIVE_KEYS = {"GIT_TOKEN", "REGISTRY_TOKEN", "REGISTRY_AUTHS"}


def _get_cipher():
    """Derive a Fernet key from JWT_SHARED_SECRET."""
    from cryptography.fernet import Fernet
    secret = os.environ.get("JWT_SHARED_SECRET", "")
    if not secret:
        if os.environ.get("FASTAPI_ENV") != "production":
            import logging
            secret = secrets.token_hex(32)
            logging.getLogger(__name__).warning("[security] JWT_SHARED_SECRET not set — using ephemeral key for job encryption")
        else:
            raise RuntimeError("JWT_SHARED_SECRET not set — cannot encrypt job env vars")
    key = base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac('sha256', secret.encode(), b'runner-job-env-vars', 100_000)
    )
    return Fernet(key)


def _encrypt_env_vars(env_vars: dict[str, str]) -> dict[str, str]:
    """Encrypt sensitive env vars before storing in job record."""
    cipher = _get_cipher()
    result = {}
    for key, value in env_vars.items():
        if key in SENSITIVE_KEYS and value:
            result[key] = f"ENC:{cipher.encrypt(value.encode()).decode()}"
        else:
            result[key] = value
    return result


def _decrypt_env_vars(env_vars: dict[str, str]) -> dict[str, str]:
    """Decrypt sensitive env vars when assigning job to runner."""
    cipher = _get_cipher()
    result = {}
    for key, value in env_vars.items():
        if isinstance(value, str) and value.startswith("ENC:"):
            try:
                result[key] = cipher.decrypt(value[4:].encode()).decode()
            except Exception:
                result[key] = ""  # Decryption failed — empty rather than leak
        else:
            result[key] = value
    return result


def create_job(
    job_type: str,
    org: str,
    run_id: str,
    docker_image: str,
    env_vars: dict[str, str],
    expected_repo_count: int | None = None,
) -> dict[str, Any]:
    job_id = f"job-{secrets.token_hex(8)}"
    # Store expected_repo_count in env vars so it survives DB round-trip
    # (RunnerJob model only persists envVars, not arbitrary fields)
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
        "dockerImage": docker_image,
        "envVars": _encrypt_env_vars(env_vars),
    }
    write_job(job)
    return job


def assign_next_job(runner_id: str) -> dict[str, Any] | None:
    # SECURITY NOTE: This assigns the oldest queued job regardless of org.
    # This is acceptable for single-tenant deployments where all runners are
    # trusted. The Runner model has no org/allowed_orgs field by design.
    #
    # TODO(multi-tenant): For multi-tenant deployments, add org-scoped runner
    # groups. Runners should declare allowed_orgs and this function must filter
    # queued jobs to only those whose job["org"] is in the runner's allowed set.
    # See also: Runner model in src/db/models.py (needs allowed_orgs column).
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


def update_job_status(job_id: str, status: str, **kwargs: Any) -> dict[str, Any] | None:
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
    job = update_job_status(job_id, "completed")
    if job and job.get("runnerId"):
        runner = read_runner(job["runnerId"])
        if runner:
            runner["jobsCompleted"] = runner.get("jobsCompleted", 0) + 1
            write_runner(runner)
    return job


def fail_job(job_id: str, error: str) -> dict[str, Any] | None:
    return update_job_status(job_id, "failed", error=error)


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

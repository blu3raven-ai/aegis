# backend/src/runner/router.py
"""Runner-facing API endpoints.

Endpoints for the runner agent to register, heartbeat, poll for jobs,
post progress, and report failures.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.runner.jobs import (
    assign_next_job,
    complete_job,
    fail_job,
    read_job,
    requeue_stale_jobs,
    update_job_progress,
)
from src.runner.registry import (
    authenticate_runner,
    heartbeat,
    register_runner,
    rotate_auth_token,
)
from src.shared.event_bus import Event, get_event_bus
from src.shared.paths import now_iso
from src.shared.rate_limit import rate_limit_by_ip

router = APIRouter(prefix="/runner/api", tags=["runner"])


def _runner_from_request(request: Request) -> dict[str, Any] | None:
    """Extract and authenticate runner from Authorization header."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    return authenticate_runner(token)


def _require_runner(request: Request) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Authenticate runner or return 401 response."""
    runner = _runner_from_request(request)
    if not runner:
        return None, JSONResponse({"error": "Unauthorized"}, status_code=401)
    return runner, None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    token: str
    name: str = ""
    os: str = ""
    arch: str = ""


@router.post("/register")
def register(request: Request, body: RegisterRequest) -> JSONResponse:
    rate_limit_by_ip(request, 5, 300)
    runner, raw_auth, error = register_runner(
        raw_token=body.token,
        name=body.name,
        os_name=body.os,
        arch=body.arch,
    )
    if error:
        return JSONResponse({"error": error}, status_code=400)
    return JSONResponse({
        "runnerId": runner["id"],
        "authToken": raw_auth,
        "status": runner["status"],
        "config": {
            "maxConcurrent": runner.get("maxConcurrent", 2),
        },
    })


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class HeartbeatRequest(BaseModel):
    cpuPercent: float | None = None
    memoryUsedGb: float | None = None
    memoryTotalGb: float | None = None
    diskUsedGb: float | None = None
    diskTotalGb: float | None = None
    cores: int | None = None
    activeContainers: list[dict[str, Any]] | None = None
    scannerImages: dict[str, Any] | None = None
    os: str | None = None
    arch: str | None = None


@router.post("/heartbeat")
def post_heartbeat(request: Request, body: HeartbeatRequest | None = None) -> JSONResponse:
    runner, err = _require_runner(request)
    if err:
        return err

    metrics = body.model_dump(exclude_none=True) if body else None
    updated = heartbeat(runner["id"], metrics)
    if not updated:
        return JSONResponse({"error": "Runner not found"}, status_code=404)

    get_event_bus().publish_sync(Event(
        event_type="runner.status",
        data={
            "runnerId": runner["id"],
            "name": runner.get("name", ""),
            "status": "online",
            "lastHeartbeat": now_iso(),
        },
        require_admin=True,
    ))

    response: dict[str, Any] = {"ok": True, "status": updated.get("status")}

    # Return config so runner can adjust settings dynamically
    response["config"] = {
        "maxConcurrent": updated.get("maxConcurrent", 2),
    }

    return JSONResponse(response)


# ---------------------------------------------------------------------------
# Job polling
# ---------------------------------------------------------------------------


@router.get("/jobs/next")
def poll_next_job(request: Request) -> JSONResponse:
    runner, err = _require_runner(request)
    if err:
        return err

    if runner.get("status") != "approved":
        return JSONResponse({"error": "Runner not approved"}, status_code=403)

    # Re-queue any stale jobs before assigning
    requeue_stale_jobs()

    job = assign_next_job(runner["id"])
    if not job:
        from starlette.responses import Response
        return Response(status_code=204)

    # Transition scan run from "queued" to "running" now that runner claimed the job
    _transition_run_to_running(job)

    # Return job payload (includes decrypted env vars)
    return JSONResponse({
        "jobId": job["id"],
        "type": job.get("jobType", ""),
        "org": job["org"],
        "runId": job["runId"],
        "dockerImage": job["dockerImage"],
        "dockerArgs": {"envVars": job.get("envVars", {})},
        "expectedRepoCount": int(job.get("envVars", {}).get("EXPECTED_REPO_COUNT", 0)) or None,
    })


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------


class ProgressRequest(BaseModel):
    logTail: list[str] = []
    progress: dict[str, Any] = {}


@router.post("/jobs/{job_id}/progress")
def post_progress(job_id: str, body: ProgressRequest, request: Request) -> JSONResponse:
    runner, err = _require_runner(request)
    if err:
        return err

    job = read_job(job_id)
    if not job:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    if job.get("runnerId") != runner["id"]:
        return JSONResponse({"error": "Not your job"}, status_code=403)

    update_job_progress(job_id, body.logTail, body.progress)

    # Also update the scan run record so the dashboard shows progress
    _sync_progress_to_run(job, body.logTail, body.progress)

    # Re-read job to check if it was cancelled while we were processing
    current = read_job(job_id)
    cancelled = current and current.get("status") == "cancelled"
    return JSONResponse({"ok": True, "cancelled": cancelled})


def _transition_run_to_running(job: dict[str, Any]) -> None:
    """Transition scan run from queued to running when runner claims the job."""
    job_type = job.get("jobType")
    org = job.get("org", "")
    run_id = job.get("runId", "")
    if not org or not run_id:
        return

    patch = {"status": "running", "startedAt": now_iso()}
    _update_run_status(job_type, org, run_id, patch)


def _sync_progress_to_run(job: dict[str, Any], log_tail: list[str], progress: dict[str, Any]) -> None:
    """Sync job progress to the corresponding scan run record.

    The runner sends cumulative counters from real-time log parsing.
    We take max(runner, db) to prevent regression and preserve expectedRepos.
    """
    job_type = job.get("jobType")
    org = job.get("org", "")
    run_id = job.get("runId", "")
    if not org or not run_id:
        return

    # Read current run to get expectedRepos and existing counters
    current = None
    if job_type == "dependencies":
        from src.storage import update_dependencies_run, list_dependencies_runs
        current = next((r for r in list_dependencies_runs(org) if str(r.get("id", "")) == run_id), None)
    elif job_type == "secrets":
        from src.storage import update_secret_run, read_secret_run
        current = read_secret_run(org, run_id)
    elif job_type == "code_scanning":
        from src.storage import update_code_scanning_run, list_code_scanning_runs
        current = next((r for r in list_code_scanning_runs(org) if str(r.get("id", "")) == run_id), None)
    elif job_type == "container_scanning":
        from src.storage import update_container_scanning_run, list_container_scanning_runs
        current = next((r for r in list_container_scanning_runs(org) if str(r.get("id", "")) == run_id), None)

    db = (current or {}).get("progress") or {}

    # Runner counters are cumulative — take max with DB to never regress
    from src.secrets.scanner import compute_running_percent
    scanned = max(int(db.get("scannedRepos") or 0), int(progress.get("scannedRepos") or 0))
    finished = max(int(db.get("finishedRepos") or 0), int(progress.get("finishedRepos") or 0))
    expected = db.get("expectedRepos") or progress.get("expectedRepos") or 0
    merged = {
        **progress,
        "scannedRepos": scanned,
        "finishedRepos": finished,
        "expectedRepos": expected,
        "percent": compute_running_percent(expected, scanned, finished),
    }
    patch: dict[str, Any] = {"logTail": log_tail, "progress": merged}

    if job_type == "dependencies":
        update_dependencies_run(org, run_id, patch)
    elif job_type == "secrets":
        update_secret_run(org, run_id, patch)
    elif job_type == "code_scanning":
        update_code_scanning_run(org, run_id, patch)
    elif job_type == "container_scanning":
        update_container_scanning_run(org, run_id, patch)

    # Publish SSE event
    tool_label = {"dependencies": "dependencies", "code_scanning": "code_scanning", "secrets": "secrets", "container_scanning": "container_scanning"}.get(job_type)
    if tool_label:
        log_tail_trimmed = (log_tail or [])[-8:]
        get_event_bus().publish_sync(Event(
            event_type="scan.progress",
            data={
                "tool": tool_label,
                "org": org,
                "runId": run_id,
                "progress": merged,
                "logTail": log_tail_trimmed,
            },
            org=org,
        ))


# ---------------------------------------------------------------------------
# Job completion (MinIO-based upload flow)
# ---------------------------------------------------------------------------


class CompleteRequest(BaseModel):
    filesUploaded: int = 0
    filesFailed: int = 0


@router.post("/jobs/{job_id}/complete")
async def complete_job_endpoint(job_id: str, body: CompleteRequest, request: Request) -> JSONResponse:
    runner, err = _require_runner(request)
    if err:
        return err

    job = read_job(job_id)
    if not job:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    if job.get("runnerId") != runner["id"]:
        return JSONResponse({"error": "Not your job"}, status_code=403)

    # If the job was already cancelled, don't overwrite with "completed"
    if job.get("status") == "cancelled":
        return JSONResponse({"ok": True, "skipped": "job_cancelled"})

    complete_job(job_id)

    # Trigger async ingestion from MinIO in a background thread
    import threading
    threading.Thread(
        target=_ingest_from_minio,
        args=(job,),
        daemon=True,
    ).start()

    # Auto-rotate auth token
    new_raw, _ = rotate_auth_token(runner["id"])
    response: dict[str, Any] = {"ok": True}
    if new_raw:
        response["newAuthToken"] = new_raw

    return JSONResponse(response)


def _ingest_from_minio(job: dict[str, Any]) -> None:
    """Ingest scan results from MinIO after runner uploads. Runs in background thread."""
    import logging
    _logger = logging.getLogger(__name__)

    org = job.get("org", "")
    run_id = job.get("runId", "")
    job_type = job.get("jobType", "dependencies")

    # If the run was already cancelled, don't overwrite with ingestion
    run_record = _read_run_record(job_type, org, run_id)
    if run_record and run_record.get("status") == "cancelled":
        _logger.info("[–] Skipping ingestion for cancelled run %s %s/%s", job_type, org, run_id)
        return

    # Update run status to "ingesting" so the dashboard shows what's happening
    _update_run_status(job_type, org, run_id, {"status": "ingesting", "progress": {"stage": "ingesting"}})

    try:
        if job_type == "dependencies":
            from src.dependencies.scanner import ingest_dependencies_from_minio
            ingest_dependencies_from_minio(org, run_id)
        elif job_type == "secrets":
            from src.secrets.scanner import ingest_secrets_from_minio
            ingest_secrets_from_minio(org, run_id)
        elif job_type == "code_scanning":
            from src.code_scanning.scanner import ingest_code_scanning_from_minio
            ingest_code_scanning_from_minio(org, run_id)
        elif job_type == "container_scanning":
            from src.containers.scanner import ingest_container_from_minio
            ingest_container_from_minio(org, run_id)
        _logger.info("[✓] Ingestion completed for %s %s/%s", job_type, org, run_id)
        get_event_bus().publish_sync(Event(
            event_type="scan.completed",
            data={"tool": job_type, "org": org, "runId": run_id},
            org=org,
        ))
        # Emit notifications
        from src.notifications.emitter import notify_scan_completed
        run_record = _read_run_record(job_type, org, run_id)
        counts = (run_record or {}).get("counts")
        notify_scan_completed(job_type, org, run_id, counts)
    except Exception as e:
        _logger.exception("[!] Ingestion failed for %s %s/%s: %s", job_type, org, run_id, e)
        _update_run_status(job_type, org, run_id, {
            "status": "failed",
            "finishedAt": now_iso(),
            "error": f"Ingestion failed: {e}",
        })
        fail_job(job.get("id", ""), str(e))
        get_event_bus().publish_sync(Event(
            event_type="scan.failed",
            data={"tool": job_type, "org": org, "runId": run_id, "error": str(e)},
            org=org,
        ))
        from src.notifications.emitter import notify_scan_failed
        notify_scan_failed(job_type, org, run_id, str(e))


def _read_run_record(job_type: str, org: str, run_id: str) -> dict[str, Any] | None:
    """Read a scan run record by tool type. Returns None if not found."""
    try:
        if job_type == "dependencies":
            from src.storage import list_dependencies_runs
            return next((r for r in list_dependencies_runs(org) if str(r.get("id", "")) == run_id), None)
        elif job_type == "code_scanning":
            from src.storage import list_code_scanning_runs
            return next((r for r in list_code_scanning_runs(org) if str(r.get("id", "")) == run_id), None)
        elif job_type == "secrets":
            from src.storage import read_secret_run
            return read_secret_run(org, run_id)
        elif job_type == "container_scanning":
            from src.storage import list_container_scanning_runs
            return next((r for r in list_container_scanning_runs(org) if str(r.get("id", "")) == run_id), None)
    except Exception:
        pass
    return None


def _update_run_status(job_type: str, org: str, run_id: str, patch: dict[str, Any]) -> None:
    """Update a scan run record by tool type."""
    try:
        if job_type == "dependencies":
            from src.storage import update_dependencies_run
            update_dependencies_run(org, run_id, patch)
        elif job_type == "secrets":
            from src.storage import update_secret_run
            update_secret_run(org, run_id, patch)
        elif job_type == "code_scanning":
            from src.storage import update_code_scanning_run
            update_code_scanning_run(org, run_id, patch)
        elif job_type == "container_scanning":
            from src.storage import update_container_scanning_run
            update_container_scanning_run(org, run_id, patch)
    except Exception:
        import logging
        logging.getLogger(__name__).warning("[!] Failed to update %s run status for %s/%s", job_type, org, run_id, exc_info=True)


# ---------------------------------------------------------------------------
# Failure reporting
# ---------------------------------------------------------------------------


class FailRequest(BaseModel):
    error: str
    cancelled: bool = False


@router.post("/jobs/{job_id}/fail")
def report_failure(job_id: str, body: FailRequest, request: Request) -> JSONResponse:
    runner, err = _require_runner(request)
    if err:
        return err

    job = read_job(job_id)
    if not job:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    if job.get("runnerId") != runner["id"]:
        return JSONResponse({"error": "Not your job"}, status_code=403)

    fail_job(job_id, body.error)

    # Update the scan run record
    org = job.get("org", "")
    run_id = job.get("runId", "")
    job_type = job.get("jobType", "dependencies")
    status = "cancelled" if body.cancelled else "failed"
    fail_patch = {"status": status, "finishedAt": now_iso(), "error": body.error}

    if job_type == "dependencies":
        from src.storage import update_dependencies_run
        update_dependencies_run(org, run_id, fail_patch)
    elif job_type == "secrets":
        from src.storage import update_secret_run
        update_secret_run(org, run_id, fail_patch)
    elif job_type == "code_scanning":
        from src.storage import update_code_scanning_run
        update_code_scanning_run(org, run_id, fail_patch)
    elif job_type == "container_scanning":
        from src.storage import update_container_scanning_run
        update_container_scanning_run(org, run_id, fail_patch)

    return JSONResponse({"ok": True})

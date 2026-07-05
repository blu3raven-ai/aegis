"""Code scanning orchestration via runner service."""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.shared.config import build_source_repo_list, get_code_scanning_scanner_config, get_scan_sources_for_org
from src.shared.lifecycle import ScanContext, apply_lifecycle as _apply_lifecycle
from src.shared.paths import DATA_DIR, normalize_org, normalize_path_segment
from src.code_scanning.lifecycle import code_scanning_hooks
from src.storage import update_code_scanning_run

logger = logging.getLogger(__name__)

CODE_SCANNING_DATA_DIR = DATA_DIR / "code_scanning"
MAX_SCAN_DURATION_SECONDS = 12 * 60 * 60


def _execute_via_runner(
    org: str,
    run_id: str,
    config: dict[str, str],
    repo_urls: str,
    token: str,
    source_type: str | None = None,
) -> dict[str, Any] | None:
    """Create a runner job and poll until completion."""
    from src.runner.jobs import create_job, read_job

    env_vars = {
        "GIT_TOKEN": token,
        "GIT_REPOS": repo_urls,
        "ORG_LABEL": org,
        "CONCURRENCY": config.get("concurrency") or "4",
        "RUN_ID": run_id,
    }
    # The ingest resolves each finding's repo asset via SOURCE_TYPE (envVars),
    # so it must be carried through on the scheduled path too — not just on the
    # canonical "Scan now" dispatch.
    if source_type:
        env_vars["SOURCE_TYPE"] = source_type

    job = create_job(
        job_type="code_scanning",
        org=org,
        run_id=run_id,
        env_vars=env_vars,
        expected_repo_count=len(repo_urls.split(",")) if repo_urls else 0,
    )

    timeout = MAX_SCAN_DURATION_SECONDS
    start = time.time()
    while time.time() - start < timeout:
        current = read_job(job["id"])
        if not current:
            break
        if current["status"] in ("completed", "failed", "cancelled"):
            return current
        time.sleep(5)

    return None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")




class InMemoryScanRuntime:
    def __init__(self) -> None:
        self._jobs: dict[str, Any] = {}
        self._cancelled: set[str] = set()
        self._lock = threading.Lock()

    def _key(self, org: str) -> str:
        return org.strip().lower()

    def start(self, org: str, run_id: str) -> bool:
        key = self._key(org)
        with self._lock:
            if key in self._jobs:
                return False
            self._jobs[key] = {"org": org, "run_id": run_id, "container_name": None, "child_pid": None}
            self._cancelled.discard(run_id)
            return True

    def set_process_meta(self, org: str, **kwargs) -> None:
        key = self._key(org)
        with self._lock:
            job = self._jobs.get(key)
            if job:
                job.update(kwargs)

    def cancel(self, org: str, cancel_fn=None) -> dict[str, Any]:
        key = self._key(org)
        with self._lock:
            job = self._jobs.get(key)
            if not job:
                return {"ok": False, "reason": "no_active_run"}
            self._cancelled.add(job["run_id"])
            container = job.get("container_name")
            child_pid = job.get("child_pid")
        if cancel_fn:
            cancel_fn(container_name=container, child_pid=child_pid)
        with self._lock:
            self._jobs.pop(key, None)
        return {"ok": True, "runId": job["run_id"]}

    def is_cancelled(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._cancelled

    def discard_cancelled(self, run_id: str) -> None:
        with self._lock:
            self._cancelled.discard(run_id)

    def release(self, org: str) -> None:
        key = self._key(org)
        with self._lock:
            job = self._jobs.pop(key, None)
            if job:
                self._cancelled.discard(job["run_id"])

    def probe(self, org: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(self._key(org))
            if not job:
                return {"active": False, "runId": None}
            return {"active": True, "runId": job["run_id"]}


def _build_run_output_dir(org: str, run_id: str) -> Path:
    return CODE_SCANNING_DATA_DIR / "raw" / normalize_org(org) / normalize_path_segment(run_id)


def ingest_code_scanning_from_minio(org: str, run_id: str, source_type: str | None = None) -> None:
    """Ingest code scanning results from object store after runner completion."""
    from src.shared.object_store import find_findings_jsonl
    from src.code_scanning.ingest import ingest_findings_jsonl
    import tempfile

    data = find_findings_jsonl(f"code_scanning/{org}/{run_id}/")
    all_findings: list[dict[str, Any]] = []

    if data is None:
        logger.warning("No code scanning output for %s/%s", org, run_id)
        update_code_scanning_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": "No output files found"})
        return

    if data:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".jsonl", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            all_findings = ingest_findings_jsonl(Path(tmp_path))
        finally:
            os.unlink(tmp_path)

    # Skip lifecycle on empty results — could be scanner errors, not truly 0 findings
    new_findings: list[dict[str, Any]] = []
    if all_findings:
        ctx = ScanContext(tool="code_scanning", org=org, run_id=run_id, source_type=source_type)
        new_findings = _apply_lifecycle(code_scanning_hooks, ctx, all_findings)

        try:
            from src.settings.llm.usage import record_usage_from_findings
            record_usage_from_findings(all_findings)
        except Exception:
            logger.warning("Failed to record LLM usage from code_scanning ingest", exc_info=True)

    if new_findings:
        try:
            from src.notifications.emitter import notify_new_critical_findings
            notify_new_critical_findings("code_scanning", org, new_findings)
        except Exception:
            logger.warning("Failed to emit new finding notifications", exc_info=True)

        from src.shared.event_emit_helpers import emit_finding_created
        for finding in new_findings:
            emit_finding_created(
                finding=finding,
                scanner_type="sast",
                source_component="code_scanning.scanner",
            )

    # Guard against race: don't overwrite a concurrent cancellation
    from src.storage import list_code_scanning_runs
    current = next((r for r in list_code_scanning_runs(org) if r.get("id") == run_id), None)
    if current and current.get("status") == "cancelled":
        logger.info("Skipping completion — run %s already cancelled", run_id)
        return

    update_code_scanning_run(org, run_id, {
        "status": "completed",
        "finishedAt": now_iso(),
        "findingsCount": len(all_findings),
        "progress": {"percent": 100, "stage": "completed"},
    })

    # Write per-asset checkpoints so coverage gaps can be computed
    from src.assets.service import resolve_repo_asset_ids
    from src.shared.checkpoints import write_checkpoint
    repos = build_source_repo_list(get_scan_sources_for_org(org))
    asset_ids = resolve_repo_asset_ids([r["full_name"] for r in repos])
    for full_name, asset_id in asset_ids.items():
        write_checkpoint("code_scanning", asset_id)


def execute_code_scanning_scan_once(
    org: str,
    token: str,
    run_id: str,
    *,
    source_type: str | None = None,
    scanner_config: dict[str, str] | None = None,
    scan_mode: str = "full",
    runtime: InMemoryScanRuntime | None = None,
) -> dict[str, Any] | None:
    """Run code scanning scan for an org."""
    runtime_started = runtime.start(org, run_id) if runtime else False
    if runtime and not runtime_started:
        return None

    config = scanner_config or get_code_scanning_scanner_config()

    update_code_scanning_run(org, run_id, {"scanMode": scan_mode})

    all_sources = [s for s in get_scan_sources_for_org(org) if s.repo_urls]
    total_repos = sum(len(s.repo_urls) for s in all_sources)
    update_code_scanning_run(org, run_id, {
        "progress": {"expectedRepos": total_repos, "scannedRepos": 0, "finishedRepos": 0, "percent": 0, "stage": "scanning"},
    })

    try:
        sources = get_scan_sources_for_org(org)
        repo_sources = [s for s in sources if s.repo_urls]

        if not repo_sources:
            update_code_scanning_run(org, run_id, {
                "status": "completed",
                "finishedAt": now_iso(),
                "findingsCount": 0,
                "error": None,
            })
            if runtime and runtime_started:
                runtime.release(org)
            return {"org": org, "findings": [], "meta": {"lastRefreshedAt": now_iso(), "runId": run_id}}

        all_repo_urls: list[str] = []
        source_token = token
        for source in repo_sources:
            all_repo_urls.extend(source.repo_urls)
            if source.token:
                source_token = source.token

        repo_urls_str = ",".join(all_repo_urls)

        result = _execute_via_runner(
            org=org,
            run_id=run_id,
            config=config,
            repo_urls=repo_urls_str,
            token=source_token,
            source_type=source_type,
        )

        if runtime and runtime.is_cancelled(run_id):
            return None

        if not result or result.get("status") in ("failed", "cancelled"):
            failure_msg = result.get("error", "Runner job failed") if result else "Runner job timed out"
            update_code_scanning_run(org, run_id, {
                "status": "failed",
                "finishedAt": now_iso(),
                "error": failure_msg,
            })
            if runtime and runtime_started:
                runtime.release(org)
            return None

        # Final status set by ingest_code_scanning_from_minio on runner callback
        return {"org": org, "meta": {"lastRefreshedAt": now_iso(), "runId": run_id}}

    except Exception:
        logger.exception("Code scanning scan failed for %s", org)
        update_code_scanning_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": "Scan failed unexpectedly. Check server logs for details."})
        return None
    finally:
        if runtime:
            runtime.discard_cancelled(run_id)
            if runtime_started:
                runtime.release(org)


_code_scanning_runtime = InMemoryScanRuntime()

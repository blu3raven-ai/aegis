"""IaC scanning — ingest checkov findings from object store, plus the scheduled
auto-rerun entrypoint (mirrors the code-scanning scanner)."""
from __future__ import annotations

import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.code_scanning.scanner import InMemoryScanRuntime
from src.iac.lifecycle import iac_scanning_hooks
from src.shared.lifecycle import ScanContext, apply_lifecycle as _apply_lifecycle
from src.storage import update_iac_run

logger = logging.getLogger(__name__)

MAX_SCAN_DURATION_SECONDS = 12 * 60 * 60


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ingest_iac_from_minio(org: str, run_id: str, source_type: str | None = None) -> None:
    """Ingest IaC scanning results from object store after runner completion."""
    from src.shared.object_store import find_findings_jsonl
    from src.iac.ingest import read_iac_findings

    data = find_findings_jsonl(f"iac_scanning/{org}/{run_id}/")
    all_findings: list[dict[str, Any]] = []

    if data is None:
        logger.warning("No IaC scanning output for %s/%s", org, run_id)
        update_iac_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": "No output files found"})
        return

    if data:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".jsonl", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            all_findings = read_iac_findings(Path(tmp_path))
        finally:
            os.unlink(tmp_path)

    # Skip lifecycle on empty results — could be scanner errors, not truly 0 findings
    new_findings: list[dict[str, Any]] = []
    if all_findings:
        ctx = ScanContext(tool="iac_scanning", org=org, run_id=run_id, source_type=source_type)
        new_findings = _apply_lifecycle(iac_scanning_hooks, ctx, all_findings)

        try:
            from src.settings.llm.usage import record_usage_from_findings
            record_usage_from_findings(all_findings)
        except Exception:
            logger.warning("Failed to record LLM usage from iac ingest", exc_info=True)

    if new_findings:
        try:
            from src.notifications.emitter import notify_new_critical_findings
            notify_new_critical_findings("iac_scanning", org, new_findings)
        except Exception:
            logger.warning("Failed to emit new finding notifications", exc_info=True)

        from src.shared.event_emit_helpers import emit_finding_created
        for finding in new_findings:
            emit_finding_created(
                finding=finding,
                scanner_type="iac",
                source_component="iac.scanner",
            )

    # Guard against race: don't overwrite a concurrent cancellation
    from src.storage import list_iac_runs
    current = next((r for r in list_iac_runs(org) if r.get("id") == run_id), None)
    if current and current.get("status") == "cancelled":
        logger.info("Skipping completion — run %s already cancelled", run_id)
        return

    update_iac_run(org, run_id, {
        "status": "completed",
        "finishedAt": now_iso(),
        "findingsCount": len(all_findings),
        "progress": {"percent": 100, "stage": "completed"},
    })


def _execute_iac_via_runner(
    org: str, run_id: str, token: str, repo_urls: str, source_type: str | None,
    concurrency: str = "4",
) -> dict[str, Any] | None:
    """Create one iac_scanning runner job for the org's repos and poll it."""
    from src.runner.jobs import create_job, read_job

    env_vars = {
        "GIT_TOKEN": token,
        "GIT_REPOS": repo_urls,
        "ORG_LABEL": org,
        "CONCURRENCY": concurrency or "4",
        "RUN_ID": run_id,
    }
    # The ingest resolves assets via SOURCE_TYPE (envVars). The runner's GIT_REPOS
    # carries the clone URLs; SOURCE_TYPE tells the backend which connection they
    # belong to.
    if source_type:
        env_vars["SOURCE_TYPE"] = source_type

    job = create_job(
        job_type="iac_scanning", org=org, run_id=run_id, env_vars=env_vars,
        expected_repo_count=len(repo_urls.split(",")) if repo_urls else 0,
    )

    start = time.time()
    while time.time() - start < MAX_SCAN_DURATION_SECONDS:
        current = read_job(job["id"])
        if not current:
            break
        if current["status"] in ("completed", "failed", "cancelled"):
            return current
        time.sleep(5)
    return None


def execute_iac_scan_once(
    org: str, token: str, run_id: str, *,
    source_type: str | None = None,
    runtime: "InMemoryScanRuntime | None" = None,
) -> dict[str, Any] | None:
    """Run an IaC scan for an org (one runner job across its repos).

    Mirrors execute_code_scanning_scan_once: the success status is set by
    ingest_iac_from_minio on the runner callback; this only handles dispatch,
    progress seeding, and failure.
    """
    from src.shared.config import get_scan_sources_for_org

    runtime_started = runtime.start(org, run_id) if runtime else False
    if runtime and not runtime_started:
        return None

    try:
        sources = [s for s in get_scan_sources_for_org(org) if s.repo_urls]
        total_repos = sum(len(s.repo_urls) for s in sources)
        update_iac_run(org, run_id, {
            "progress": {"expectedRepos": total_repos, "scannedRepos": 0, "finishedRepos": 0, "percent": 0, "stage": "scanning"},
        })

        if not sources:
            update_iac_run(org, run_id, {"status": "completed", "finishedAt": now_iso(), "findingsCount": 0, "error": None})
            return {"org": org, "meta": {"runId": run_id}}

        all_repo_urls: list[str] = []
        source_token = token
        for source in sources:
            all_repo_urls.extend(source.repo_urls)
            if source.token:
                source_token = source.token

        result = _execute_iac_via_runner(
            org=org, run_id=run_id, token=source_token,
            repo_urls=",".join(all_repo_urls), source_type=source_type,
        )

        if runtime and runtime.is_cancelled(run_id):
            return None

        if not result or result.get("status") in ("failed", "cancelled"):
            msg = result.get("error", "Runner job failed") if result else "Runner job timed out"
            update_iac_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": msg})
            return None

        return {"org": org, "meta": {"runId": run_id}}

    except Exception:
        logger.exception("IaC scan failed for %s", org)
        update_iac_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": "Scan failed unexpectedly. Check server logs for details."})
        return None
    finally:
        if runtime:
            runtime.discard_cancelled(run_id)
            if runtime_started:
                runtime.release(org)


_iac_runtime = InMemoryScanRuntime()

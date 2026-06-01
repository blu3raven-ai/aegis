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
from src.storage import (
    update_code_scanning_run,
    read_code_scanning_findings,
    patch_finding_detail,
)

logger = logging.getLogger(__name__)

CODE_SCANNING_SCANNER_IMAGE = "aegis/scanner-code-scanning:latest"
CODE_SCANNING_DATA_DIR = DATA_DIR / "code_scanning"
MAX_SCAN_DURATION_SECONDS = 12 * 60 * 60


def _try_incremental_sast_scan(
    repo_id: str,
    checkout_path: Path,
    baseline_sha: str | None,
    head_sha: str,
    rule_pack_version: str,
) -> list[dict[str, Any]] | None:
    """Return findings if an incremental SAST scan succeeded; None to fall through.

    Guarded by AEGIS_USE_INCREMENTAL_SAST=true (default: false) so existing
    full-scan behaviour is unchanged when the flag is absent.

    Any exception — including NotImplementedError from adapter stubs — is
    caught; the caller gets None and the full scan runs instead.
    """
    if os.getenv("AEGIS_USE_INCREMENTAL_SAST", "false").lower() != "true":
        return None
    try:
        from src.code_scanning.baseline_delta import SastBaselineDelta
        from src.code_scanning.file_finding_cache import FileFindingCache
        from src.code_scanning.opengrep_adapter import run_opengrep

        engine = SastBaselineDelta(
            cache=FileFindingCache(),
            opengrep_runner=run_opengrep,
        )
        result = engine.scan(
            repo_id=repo_id,
            checkout_path=checkout_path,
            baseline_sha=baseline_sha,
            head_sha=head_sha,
            rule_pack_version=rule_pack_version,
        )
        logger.info(
            "incremental sast scan: cached_files=%d rescanned=%d deleted=%d findings=%d",
            result.cached_files,
            result.rescanned_files,
            result.deleted_files,
            len(result.findings),
        )
        # Convert Finding dataclass instances to plain dicts for the ingest path
        return [f if isinstance(f, dict) else vars(f) for f in result.findings]
    except Exception:
        logger.exception("incremental sast scan failed; falling through to full scan")
        return None


def _finalize_incremental_sast_scan(
    org: str,
    run_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Persist incremental SAST findings and mark the run complete.

    Called inline when the incremental SAST engine has already produced a
    findings list, bypassing the scanner runner.
    """
    new_findings: list[dict[str, Any]] = []
    if findings:
        ctx = ScanContext(tool="code_scanning", org=org, run_id=run_id)
        new_findings = _apply_lifecycle(code_scanning_hooks, ctx, findings)

    if new_findings:
        try:
            from src.notifications.emitter import notify_new_critical_findings
            notify_new_critical_findings("code_scanning", org, new_findings)
        except Exception:
            logger.warning("Failed to emit new finding notifications", exc_info=True)

        from src.shared.event_emit_helpers import emit_finding_created
        for finding in new_findings:
            emit_finding_created(
                org_id=org,
                finding=finding,
                scanner_type="sast",
                source_component="code_scanning.scanner",
            )

    update_code_scanning_run(org, run_id, {
        "status": "completed",
        "finishedAt": now_iso(),
        "findingsCount": len(findings),
        "progress": {"percent": 100, "stage": "completed"},
    })


def _execute_via_runner(
    org: str,
    run_id: str,
    config: dict[str, str],
    repo_urls: str,
    token: str,
    rulesets: str,
) -> dict[str, Any] | None:
    """Create a runner job and poll until completion."""
    from src.runner.jobs import create_job, read_job

    job = create_job(
        job_type="code_scanning",
        org=org,
        run_id=run_id,
        docker_image=config.get("image") or CODE_SCANNING_SCANNER_IMAGE,
        env_vars={
            "GIT_TOKEN": token,
            "GIT_REPOS": repo_urls,
            "ORG_LABEL": org,
            "CONCURRENCY": config.get("concurrency") or "4",
            "RUN_ID": run_id,
            "RULESETS": rulesets,
        },
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


async def _run_ai_classification(
    org: str,
    run_id: str,
    code_scanning_config: dict[str, Any],
    runtime: InMemoryScanRuntime | None,
) -> None:
    """Run AI review on open findings lacking an ai_review entry."""
    from src.code_scanning.ai_review import review_code_scanning_finding, CodeScanningAiReviewError, _get_tier

    findings = read_code_scanning_findings(org)
    if not findings:
        return

    target_keys = [
        code_scanning_hooks.compute_identity_key(f)
        for f in findings
        if f.get("state") == "open" and not f.get("ai_review") and _get_tier(f) != "skip"
    ]
    total = len(target_keys)
    if total == 0:
        return

    reviewed = 0
    for key in target_keys:
        if runtime and runtime.is_cancelled(run_id):
            break

        # Re-read each iteration to avoid overwriting concurrent dismiss/reopen
        current_findings = read_code_scanning_findings(org)
        if not current_findings:
            break
        target_finding = next(
            (f for f in current_findings if code_scanning_hooks.compute_identity_key(f) == key),
            None,
        )
        if not target_finding or target_finding.get("ai_review"):
            reviewed += 1
            continue

        try:
            result = await review_code_scanning_finding(target_finding, code_scanning_config)
            logger.info("AI review for %s: %s", target_finding.get("rule_id"), result.get("classification", "unknown"))
            patch_finding_detail("code_scanning", org, key, {"aiReview": result})
        except CodeScanningAiReviewError as exc:
            logger.warning("AI review failed for finding %s: %s", target_finding.get("rule_id"), exc)
        except Exception as exc:
            logger.warning("Unexpected AI review error for finding %s: %s", target_finding.get("rule_id"), exc)

        reviewed += 1
        update_code_scanning_run(org, run_id, {
            "status": "ingesting",
            "progress": {
                "stage": "ai_review",
                "reviewed": reviewed,
                "total": total,
                "percent": min(99, int((reviewed / total) * 100)),
            },
        })


def ingest_code_scanning_from_minio(org: str, run_id: str) -> None:
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
        ctx = ScanContext(tool="code_scanning", org=org, run_id=run_id)
        new_findings = _apply_lifecycle(code_scanning_hooks, ctx, all_findings)

    if new_findings:
        try:
            from src.notifications.emitter import notify_new_critical_findings
            notify_new_critical_findings("code_scanning", org, new_findings)
        except Exception:
            logger.warning("Failed to emit new finding notifications", exc_info=True)

        from src.shared.event_emit_helpers import emit_finding_created
        for finding in new_findings:
            emit_finding_created(
                org_id=org,
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

    # Write per-repo checkpoints so coverage gaps can be computed
    from src.shared.checkpoints import write_checkpoint
    for repo in build_source_repo_list(get_scan_sources_for_org(org)):
        write_checkpoint("code_scanning", org, repo["full_name"])


def execute_code_scanning_scan_once(
    org: str,
    token: str,
    run_id: str,
    *,
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

    # AI Review Only: skip runner, classify existing findings directly
    if scan_mode == "ai_review_only":
        try:
            update_code_scanning_run(org, run_id, {
                "status": "ingesting",
                "progress": {"stage": "ai_review", "percent": 0},
            })
            import asyncio
            asyncio.run(_run_ai_classification(org, run_id, config, runtime))

            from src.storage import list_code_scanning_runs
            current = next((r for r in list_code_scanning_runs(org) if r.get("id") == run_id), None)
            if current and current.get("status") == "cancelled":
                logger.info("Skipping completion — run %s already cancelled", run_id)
                return None

            update_code_scanning_run(org, run_id, {
                "status": "completed",
                "finishedAt": now_iso(),
                "progress": {"percent": 100, "stage": "completed"},
            })
            return {"org": org, "meta": {"lastRefreshedAt": now_iso(), "runId": run_id}}
        except Exception:
            logger.exception("AI review failed for %s", org)
            update_code_scanning_run(org, run_id, {
                "status": "failed",
                "finishedAt": now_iso(),
                "error": "AI review failed unexpectedly. Check server logs for details.",
            })
            return None
        finally:
            if runtime:
                runtime.discard_cancelled(run_id)
                if runtime_started:
                    runtime.release(org)

    run_output_dir = _build_run_output_dir(org, run_id)

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
        rulesets = config.get("rulesets") or (
            "p/owasp-top-ten,p/cwe-top-25,p/default,p/r2c-security-audit,"
            "p/python,p/java,p/javascript,p/typescript,p/golang,"
            "p/ruby,p/php,p/c,p/cpp,p/kotlin,p/swift,p/rust,"
            "p/django,p/flask,p/express,p/react,p/spring"
        )

        # Attempt incremental path — falls through to the runner when the
        # flag is unset, adapters are stubs, or no baseline is known.
        # head_sha uses run_id as a monotonic stand-in since no git context
        # is available here; rule_pack_version tracks the configured rulesets.
        incremental_findings = _try_incremental_sast_scan(
            repo_id=org,
            checkout_path=Path("/nonexistent"),
            baseline_sha=None,
            head_sha=run_id,
            rule_pack_version=rulesets,
        )
        if incremental_findings is not None:
            _finalize_incremental_sast_scan(org, run_id, incremental_findings)
            return {"org": org, "meta": {"lastRefreshedAt": now_iso(), "runId": run_id}}

        result = _execute_via_runner(
            org=org,
            run_id=run_id,
            config=config,
            repo_urls=repo_urls_str,
            token=source_token,
            rulesets=rulesets,
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

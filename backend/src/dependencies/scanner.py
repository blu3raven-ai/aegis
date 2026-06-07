"""Dependency scanning orchestration via runner service."""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Literal

from src.shared.checkpoints import write_checkpoint
from src.shared.config import get_dependencies_scanner_config, get_scan_sources_for_org, read_app_config
from src.shared.object_store import (
    download_json,
    download_bytes,
    delete_prefix,
    list_objects,
    tag_object,
)
from src.shared.enrichment import ingest_findings_jsonl, enrich_findings_with_advisory_data
from src.shared.paths import DATA_DIR
from src.dependencies.lifecycle import dependencies_hooks
from src.dependencies.sbom_store import upsert_sbom
from src.dependencies.matcher import enrich_with_manifest_snippets
from src.dependencies.normalizer import normalize_grype_output
from src.shared.lifecycle import ScanContext
from src.shared.lifecycle import apply_lifecycle as _apply_lifecycle
from src.storage import update_dependencies_run

logger = logging.getLogger(__name__)


DEPENDENCIES_DATA_DIR = DATA_DIR / "dependencies"
MAX_SCAN_DURATION_SECONDS = 12 * 60 * 60


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class RuntimeJob:
    org: str
    run_id: str
    container_name: str | None = None
    child_pid: int | None = None


class InMemoryScanRuntime:
    def __init__(self) -> None:
        self._jobs: dict[str, RuntimeJob] = {}
        self._cancelled: set[str] = set()
        self._lock = Lock()

    def _key(self, org: str) -> str:
        return org.strip().lower()

    def start(self, org: str, run_id: str) -> bool:
        key = self._key(org)
        with self._lock:
            if key in self._jobs:
                return False
            self._jobs[key] = RuntimeJob(org=org, run_id=run_id)
            self._cancelled.discard(run_id)
            return True

    def set_process_meta(self, org: str, **kwargs) -> None:
        key = self._key(org)
        with self._lock:
            job = self._jobs.get(key)
            if job:
                if "container_name" in kwargs:
                    job.container_name = kwargs["container_name"]
                if "child_pid" in kwargs:
                    job.child_pid = kwargs["child_pid"]

    def cancel(self, org: str, cancel_fn=None) -> dict[str, Any]:
        key = self._key(org)
        with self._lock:
            job = self._jobs.get(key)
            if not job:
                return {"ok": False, "reason": "no_active_run"}
            self._cancelled.add(job.run_id)
            container = job.container_name
            child_pid = job.child_pid
        if cancel_fn:
            cancel_fn(container_name=container, child_pid=child_pid)
        with self._lock:
            self._jobs.pop(key, None)
        return {"ok": True, "runId": job.run_id}

    def is_cancelled(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._cancelled

    def release(self, org: str) -> None:
        key = self._key(org)
        with self._lock:
            job = self._jobs.pop(key, None)
            if job:
                self._cancelled.discard(job.run_id)

    def probe(self, org: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(self._key(org))
            if not job:
                return {"active": False, "runId": None}
            return {"active": True, "runId": job.run_id}


def _download_scan_output_from_minio(org: str, run_id: str) -> dict[str, dict[str, Any]]:
    """Download dependency scan output and return parsed data by repo (fallback path)."""
    prefix = f"dependencies/{org}/{run_id}/"
    keys = list_objects(prefix)
    if not keys:
        logger.warning("No scan output found for %s/%s", org, run_id)
        return {}

    # Prefer sbom.cdx.json (CycloneDX), fall back to syft.json (legacy)
    SBOM_FILENAMES = {"sbom.cdx.json", "syft.json"}
    repo_sboms: dict[str, dict[str, Any]] = {}
    sbom_keys: dict[str, str] = {}  # repo_name -> key

    for key in keys:
        relative = key[len(prefix):]
        parts = relative.split("/")
        filename = parts[-1]

        if filename in SBOM_FILENAMES and len(parts) >= 2:
            repo_name = parts[-2]
            if repo_name in sbom_keys and filename == "syft.json":
                continue
            sbom_keys[repo_name] = key
            if repo_name not in repo_sboms:
                repo_sboms[repo_name] = {"sbom": None, "head_sha": "HEAD", "manifests": {}}
            repo_sboms[repo_name]["sbom"] = download_json(key)

    for repo_path, sbom_key in sbom_keys.items():
        repo_prefix = sbom_key.rsplit("/", 1)[0] + "/"

        for key in keys:
            if not key.startswith(repo_prefix):
                continue
            filename = key[len(repo_prefix):]

            if filename == "head-sha.txt":
                data = download_bytes(key)
                if data:
                    repo_sboms[repo_path]["head_sha"] = data.decode().strip()
            elif filename == "findings.json":
                repo_sboms[repo_path]["findings_key"] = key
            elif filename.startswith("manifests/"):
                data = download_bytes(key)
                if data:
                    manifest_name = filename.replace("manifests/", "")
                    repo_sboms[repo_path]["manifests"][manifest_name] = data.decode(errors="replace")

    return repo_sboms


def _load_manifests_from_minio(prefix: str) -> dict[str, dict[str, str]]:
    """Download all manifest files from MinIO, grouped by repo name.

    MinIO layout: {prefix}{repo}/manifests/{manifest_path}
    Returns: {repo_name: {manifest_filename: content}}

    Called at ingestion time (before any retention wipe) so snippets can be
    stored permanently in the DB alongside the finding detail.
    """
    keys = list_objects(prefix)
    repo_manifests: dict[str, dict[str, str]] = {}
    for key in keys:
        relative = key[len(prefix):]
        parts = relative.split("/")
        # Expect at least: {repo}/manifests/{filename}
        if len(parts) >= 3 and parts[1] == "manifests":
            repo = parts[0]
            manifest_name = "/".join(parts[2:])
            data = download_bytes(key)
            if data:
                repo_manifests.setdefault(repo, {})[manifest_name] = data.decode(errors="replace")
    return repo_manifests


def _ingest_sboms_from_minio(org: str, run_id: str, prefix: str) -> None:
    """Find per-repo SBOMs in MinIO and populate the SbomComponent table."""
    from src.shared.object_store import list_objects, download_json
    sbom_keys = [k for k in list_objects(prefix) if k.endswith("/sbom.cdx.json")]
    for key in sbom_keys:
        # Key format: dependencies/{org}/{run_id}/{repo}/sbom.cdx.json
        parts = key.split("/")
        if len(parts) < 5:
            continue
        repo_name = parts[-2]
        sbom_json = download_json(key)
        if sbom_json:
            try:
                upsert_sbom(org=org, repo=repo_name, commit_sha="HEAD", sbom=sbom_json, manifests={}, run_id=run_id)
            except Exception:
                logger.warning("Failed to ingest SBOM for %s/%s", org, repo_name)


def ingest_dependencies_from_minio(org: str, run_id: str) -> None:
    """Ingest dependency scan results from object store after runner completion."""
    from src.shared.object_store import find_findings_jsonl
    from src.shared.enrichment import map_finding_to_alert

    prefix = f"dependencies/{org}/{run_id}/"

    findings_data = find_findings_jsonl(prefix)
    if findings_data:
        all_findings = [json.loads(line) for line in findings_data.decode().splitlines() if line.strip()]
        # Map to alert schema if not already mapped
        if all_findings and "security_advisory" not in all_findings[0]:
            all_findings = [map_finding_to_alert(f) for f in all_findings]
        # Enrich with manifest snippets from MinIO artifacts (stored before any retention wipe)
        repo_manifests = _load_manifests_from_minio(prefix)
        if repo_manifests:
            by_repo: dict[str, list[dict]] = {}
            for f in all_findings:
                repo_name = (f.get("repository") or {}).get("name", "")
                by_repo.setdefault(repo_name, []).append(f)
            for repo_name, repo_findings in by_repo.items():
                manifests = repo_manifests.get(repo_name, {})
                if manifests:
                    enrich_with_manifest_snippets(repo_findings, manifests)
        # Also process per-repo SBOMs for the SBOM Explorer
        _ingest_sboms_from_minio(org, run_id, prefix)
    elif findings_data is not None:
        all_findings = []
    else:
        repo_sboms = _download_scan_output_from_minio(org, run_id)
        if not repo_sboms:
            logger.warning("No dependency scan output for %s/%s", org, run_id)
            update_dependencies_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": "No output files found"})
            return

        all_findings = []
        for repo_name, data in repo_sboms.items():
            sbom_json = data.get("sbom")
            if not sbom_json:
                continue
            commit_sha = data.get("head_sha", "HEAD")
            manifests = data.get("manifests") or {}
            upsert_sbom(org=org, repo=repo_name, commit_sha=commit_sha, sbom=sbom_json, manifests=manifests, run_id=run_id)
            write_checkpoint("dependencies", org, repo_name, commit_sha=commit_sha)
            findings_key = data.get("findings_key") or f"dependencies/{org}/{run_id}/{repo_name}/findings.json"
            grype_output = download_json(findings_key)
            if grype_output:
                findings = normalize_grype_output(grype_output, org, repo_name, commit_sha, "grype")
                findings = enrich_with_manifest_snippets(findings, manifests)
                all_findings.extend(findings)

    deps_config = read_app_config().get("tools", {}).get("dependencies", {})
    try:
        all_findings = enrich_findings_with_advisory_data(
            all_findings,
            nvd_enabled=deps_config.get("nvdEnabled", True),
            nvd_api_key=deps_config.get("nvdApiKey", ""),
            ghsa_enabled=deps_config.get("ghsaEnabled", False),
            ghsa_api_key=deps_config.get("ghsaApiKey", ""),
        )
    except Exception:
        logger.warning("Advisory enrichment failed for %s", org)

    # Skip lifecycle on empty results — could be scanner errors, not truly 0 findings
    new_findings: list[dict[str, Any]] = []
    if all_findings:
        ctx = ScanContext(tool="dependencies", org=org, run_id=run_id, source_type=source_type)
        new_findings = _apply_lifecycle(dependencies_hooks, ctx, all_findings)

    if new_findings:
        try:
            from src.notifications.emitter import notify_new_critical_findings
            notify_new_critical_findings("dependencies", org, new_findings)
        except Exception:
            logger.warning("Failed to emit new finding notifications", exc_info=True)

        from src.shared.event_emit_helpers import emit_finding_created
        for finding in new_findings:
            emit_finding_created(
                org_id=org,
                finding=finding,
                scanner_type="dependencies",
                source_component="dependencies.scanner",
            )

    sev_counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = (f.get("security_advisory") or {}).get("severity", "").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        sev_counts["total"] += 1

    # Guard against race: don't overwrite a concurrent cancellation
    from src.storage import list_dependencies_runs
    current = next((r for r in list_dependencies_runs(org) if r.get("id") == run_id), None)
    if current and current.get("status") == "cancelled":
        logger.info("Skipping completion — run %s already cancelled", run_id)
        return

    update_dependencies_run(org, run_id, {
        "status": "completed",
        "finishedAt": now_iso(),
        "findingsCount": len(all_findings),
        "counts": sev_counts,
        "progress": {"percent": 100, "stage": "completed"},
    })


def _execute_via_runner(
    org: str,
    run_id: str,
    config: dict[str, str],
    repo_urls: str,
    token: str,
    scan_mode: str = "full",
) -> dict[str, Any] | None:
    """Create a runner job and poll until completion."""
    from src.runner.jobs import create_job, read_job

    env = {
        "GIT_TOKEN": token,
        "GIT_REPOS": repo_urls,
        "ORG_LABEL": org,
        "CONCURRENCY": config.get("concurrency") or "4",
        "RUN_ID": run_id,
        "SCAN_MODE": scan_mode,
    }
    if config.get("argusEnabled"):
        argus_endpoint = config.get("argusEndpoint", "")
        argus_api_key = config.get("argusApiKey", "")
        if argus_endpoint:
            env["ARGUS_ENDPOINT"] = argus_endpoint
        if argus_api_key:
            env["ARGUS_API_KEY"] = argus_api_key

    job = create_job(
        job_type="dependencies",
        org=org,
        run_id=run_id,
        env_vars=env,
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


def execute_dependencies_scan_once(
    org: str,
    token: str,
    run_id: str,
    *,
    source_type: str | None = None,
    scanner_config: dict[str, str] | None = None,
    mode: Literal["full", "incremental"] | None = None,
    scan_mode: str = "full",  # "full" | "sbom_only" | "advisories_only"
    runtime: InMemoryScanRuntime | None = None,
) -> dict[str, Any] | None:
    """Run dependency scan for an org."""
    runtime_started = runtime.start(org, run_id) if runtime else False
    if runtime and not runtime_started:
        return None

    config = scanner_config or get_dependencies_scanner_config()
    sources = [s for s in get_scan_sources_for_org(org) if s.repo_urls]

    total_repos = sum(len(s.repo_urls) for s in sources)
    update_dependencies_run(org, run_id, {
        "mode": mode or "full", "scanMode": scan_mode,
        "progress": {"expectedRepos": total_repos, "scannedRepos": 0, "finishedRepos": 0, "percent": 0, "stage": "scanning"},
    })

    try:
        if not sources:
            update_dependencies_run(org, run_id, {"status": "completed", "finishedAt": now_iso(), "findingsCount": 0, "error": None})
            if runtime and runtime_started:
                runtime.release(org)
            return {"org": org, "alerts": [], "analytics": {}, "meta": {"lastRefreshedAt": now_iso(), "runId": run_id}}

        succeeded_sources: list[int] = []
        failure_msg = ""

        for source_idx, source in enumerate(sources):
            if runtime and runtime.is_cancelled(run_id):
                return None

            repo_urls_str = ",".join(source.repo_urls)

            result = _execute_via_runner(
                org=org,
                run_id=run_id,
                config=config,
                repo_urls=repo_urls_str,
                token=source.token,
                scan_mode=scan_mode,
            )

            if runtime and runtime.is_cancelled(run_id):
                return None

            if not result or result.get("status") in ("failed", "cancelled"):
                failure_msg = result.get("error", "Runner job failed") if result else "Runner job timed out"
                logger.warning("Dependency source scan failed: %s", failure_msg)
            else:
                succeeded_sources.append(source_idx)

        if not succeeded_sources:
            update_dependencies_run(org, run_id, {
                "status": "failed",
                "finishedAt": now_iso(),
                "error": failure_msg or "All sources failed",
            })
            return None

        # Final status set by ingest_dependencies_from_minio on runner callback
        return {"org": org, "meta": {"lastRefreshedAt": now_iso(), "runId": run_id}}

    except Exception as error:
        logger.exception("Dependency scan failed for %s", org)
        update_dependencies_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": str(error)})
        return None
    finally:
        if runtime:
            with runtime._lock:
                runtime._cancelled.discard(run_id)
            if runtime_started:
                runtime.release(org)

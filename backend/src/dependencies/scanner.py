"""Dependency scanning orchestration via runner service."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Literal

from src.shared.config import get_dependencies_scanner_config, get_scan_sources_for_org, read_app_config
from src.shared.enrichment import enrich_findings_with_advisory_data
from src.shared.paths import DATA_DIR
from src.dependencies.lifecycle import dependencies_hooks
from src.dependencies.sbom_store import upsert_sbom
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


def _ingest_sboms_from_minio(org: str, run_id: str, source_type: str, prefix: str) -> dict[str, str]:
    """Index per-repo SBOMs into SbomComponent, resolving the repo asset first.

    Returns {asset_id: external_ref} for the repos indexed this run so the
    caller can match their components against the OSV mirror.
    """
    from src.shared.object_store import list_objects, download_json
    from src.assets.refs import repo_ref
    from src.assets.service import upsert_asset
    from src.db.helpers import run_db

    sbom_keys = [k for k in list_objects(prefix) if k.endswith("/sbom.cdx.json")]
    assets: dict[str, str] = {}
    for key in sbom_keys:
        # Key format: dependencies_scanning/{org}/{run_id}/{repo}/sbom.cdx.json
        parts = key.split("/")
        if len(parts) < 5:
            continue
        repo_name = parts[-2]
        sbom_json = download_json(key)
        if not sbom_json:
            continue
        try:
            external_ref = repo_ref(source_type, org, repo_name)
        except ValueError:
            logger.warning("Skipping repo with unresolvable source_type %r for %s/%s",
                           source_type, org, repo_name)
            continue
        display_name = f"{org}/{repo_name}"
        asset_id = run_db(lambda s, e=external_ref, d=display_name: upsert_asset(
            s, type="repo", source="source_connection", external_ref=e, display_name=d,
        ))
        try:
            upsert_sbom(
                org=org, repo=repo_name, commit_sha="HEAD", sbom=sbom_json,
                manifests={}, run_id=run_id, asset_id=asset_id,
            )
            assets[asset_id] = external_ref
        except Exception:
            logger.warning("Failed to ingest SBOM for %s/%s", org, repo_name)
    return assets


def ingest_dependencies_from_minio(org: str, run_id: str, source_type: str | None = None) -> None:
    """Ingest a dependency scan: index the uploaded SBOMs and match their
    components against the OSV mirror to produce findings.

    The runner uploads only SBOMs; vulnerability matching is done here against
    the backend's OSV mirror, then findings flow through the existing advisory
    enricher + lifecycle.
    """
    from src.db.helpers import run_db
    from src.osv.sca_findings import build_backend_match_findings

    prefix = f"dependencies_scanning/{org}/{run_id}/"

    if not source_type:
        logger.error(
            "dependency ingest for %s/%s has no source_type; cannot resolve assets", org, run_id
        )
        update_dependencies_run(org, run_id, {
            "status": "failed", "finishedAt": now_iso(),
            "error": "missing source_type for OSV matching",
        })
        return

    assets = _ingest_sboms_from_minio(org, run_id, source_type, prefix)

    async def _match(session) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for asset_id, external_ref in assets.items():
            out.extend(await build_backend_match_findings(
                session, asset_id=asset_id, external_ref=external_ref, kind="dependencies",
            ))
        return out

    all_findings: list[dict[str, Any]] = run_db(_match) if assets else []

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
        ctx = ScanContext(tool="dependencies_scanning", org=org, run_id=run_id, source_type=source_type)
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
                finding=finding,
                scanner_type="dependencies_scanning",
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
    scan_mode: str = "full",  # "full" | "sbom_only"
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


_dependencies_runtime = InMemoryScanRuntime()

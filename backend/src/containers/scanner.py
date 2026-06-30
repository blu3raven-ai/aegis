"""Container Scanner — Syft + Grype orchestration via runner service."""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from src.containers.lifecycle import container_scanning_hooks
from src.containers.sbom_store import upsert_sbom, list_stored_sboms
from src.shared.config import get_container_scanner_config, get_scan_sources_for_org
from src.shared.enrichment import enrich_findings_with_advisory_data
from src.shared.lifecycle import ScanContext, apply_lifecycle as _apply_lifecycle
from src.shared.paths import DATA_DIR
from src.storage import (
    update_container_scanning_run,
)

logger = logging.getLogger(__name__)

CONTAINER_SCANNING_DATA_DIR = DATA_DIR / "container_scanning"
MAX_SCAN_DURATION_SECONDS = 12 * 60 * 60


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _resolve_registry_username(registry: str, token: str) -> str:
    """Resolve registry username when not explicitly configured."""
    import urllib.request
    import json as _json

    # GHCR — resolve username from PAT
    if "ghcr.io" in registry and token.startswith(("ghp_", "github_pat_")):
        try:
            req = urllib.request.Request("https://api.github.com/user", headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            })
            resp = urllib.request.urlopen(req, timeout=10)
            login = _json.loads(resp.read()).get("login", "")
            if login:
                return login
        except Exception:
            pass
        logger.warning("Could not resolve GitHub username for ghcr.io — auth may fail")

    if ".dkr.ecr." in registry and ".amazonaws.com" in registry:
        return "AWS"

    # Azure ACR
    if ".azurecr.io" in registry:
        return registry.split(".")[0]

    # Google GCR / Artifact Registry
    if "gcr.io" in registry or "-docker.pkg.dev" in registry:
        return "_json_key"

    # GitLab accepts "oauth2" for PAT-based auth
    if "registry.gitlab" in registry:
        return "oauth2"

    return "_token"


def _get_previous_digests(org: str) -> dict[str, str]:
    """Get image_ref -> digest map from stored SBOMs for skip-unchanged optimization."""
    try:
        stored = list_stored_sboms(org)
        return {s["repo"]: s.get("commit_sha", "") for s in stored if s.get("commit_sha")}
    except Exception:
        return {}


def _execute_via_runner(
    org: str,
    run_id: str,
    config: dict[str, str],
    docker_images: str,
    scan_mode: str = "full",
    registry_auths: list[dict[str, str]] | None = None,
    prev_digests: dict[str, str] | None = None,
    source_type: str | None = None,
) -> dict[str, Any] | None:
    """Create a runner job and poll until completion."""
    import json as _json
    from src.runner.jobs import create_job, read_job

    env_vars = {
        "DOCKER_IMAGES": docker_images,
        "ORG_LABEL": org,
        "CONCURRENCY": config.get("concurrency") or config.get("scanConcurrency") or "4",
        "RUN_ID": run_id,
        "SCAN_MODE": scan_mode,
    }
    # The ingest resolves each image asset via SOURCE_TYPE (envVars), so it must
    # be carried through on the scheduled path too — not just on the canonical
    # "Scan now" dispatch.
    if source_type:
        env_vars["SOURCE_TYPE"] = source_type

    if prev_digests:
        env_vars["PREVIOUS_DIGESTS"] = _json.dumps(prev_digests)

    if registry_auths:
        env_vars["REGISTRY_AUTHS"] = _json.dumps(registry_auths)

    if config.get("argusEnabled") in (True, "true"):
        argus_endpoint = config.get("argusEndpoint") or os.getenv("ARGUS_ENDPOINT", "")
        argus_api_key = config.get("argusApiKey") or os.getenv("ARGUS_API_KEY", "")
        if argus_endpoint:
            env_vars["ARGUS_ENDPOINT"] = argus_endpoint
        if argus_api_key:
            env_vars["ARGUS_API_KEY"] = argus_api_key

    job = create_job(
        job_type="container_scanning",
        org=org,
        run_id=run_id,
        env_vars=env_vars,
    )
    job_id = job["id"]
    logger.info("Created runner job %s for container scan %s", job_id, run_id)

    transitioned = False
    deadline = time.time() + MAX_SCAN_DURATION_SECONDS
    while time.time() < deadline:
        j = read_job(job_id)
        if not j:
            return None
        status = j.get("status")
        if not transitioned and status != "queued":
            update_container_scanning_run(org, run_id, {
                "status": "running",
                "progress": {"stage": "scanning"},
            })
            transitioned = True
        if status in ("completed", "failed", "cancelled"):
            return j
        time.sleep(5)
    logger.error("Runner job %s timed out for run %s", job_id, run_id)
    return None


def _download_scan_output_from_minio(
    org: str, run_id: str, prefix: str
) -> dict[str, dict[str, Any]]:
    """Download SBOMs from object store. Returns {image_name: {sbom, digest}}."""
    from src.shared.object_store import list_objects, download_json, download_bytes

    keys = list_objects(prefix)
    image_sboms: dict[str, dict[str, Any]] = {}

    if not keys:
        logger.warning("No scan output found for %s/%s", org, run_id)
        return image_sboms

    for key in keys:
        rel = key[len(prefix):]
        parts = rel.split("/")
        if len(parts) < 2:
            continue

        image_safe_name = parts[0]
        filename = parts[1]

        if image_safe_name not in image_sboms:
            image_sboms[image_safe_name] = {"sbom": None, "digest": None}

        if filename == "sbom.cdx.json":
            sbom = download_json(key)
            if sbom:
                image_sboms[image_safe_name]["sbom"] = sbom
            else:
                logger.warning("Failed to read SBOM from %s", key)

        elif filename == "digest.txt":
            blob = download_bytes(key)
            if blob:
                image_sboms[image_safe_name]["digest"] = blob.decode().strip()

    return image_sboms


def _image_external_ref(source_type: str, full_ref: str) -> str:
    """Canonical image external_ref from a full image ref ('ghcr.io/acme/app:1.2.3').

    Strips the registry hostname (the registry short name is carried in
    source_type) and any digest, then builds image_ref(source_type, image, tag).
    """
    from src.assets.refs import image_ref
    ref = full_ref.split("@", 1)[0]  # drop any digest
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        ref = "/".join(parts[1:])
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        image, tag = ref.rsplit(":", 1)
    else:
        image, tag = ref, "latest"
    return image_ref(source_type, image, tag)


def _index_container_sboms(org: str, run_id: str, source_type: str, prefix: str) -> dict[str, str]:
    """Index each image SBOM under its resolved image asset.

    Returns {asset_id: external_ref} for the images indexed this run so the
    caller can match their components against the OSV mirror.
    """
    from src.assets.service import upsert_asset
    from src.db.helpers import run_db

    assets: dict[str, str] = {}
    image_sboms = _download_scan_output_from_minio(org, run_id, prefix)
    for image_safe_name, data in image_sboms.items():
        sbom = data.get("sbom")
        if not sbom:
            continue
        component = (sbom.get("metadata") or {}).get("component") or {}
        full_ref = component.get("name") or image_safe_name.replace("_", "/")
        digest = data.get("digest")
        try:
            external_ref = _image_external_ref(source_type, full_ref)
        except ValueError:
            logger.warning("Skipping image with unresolvable ref %s", full_ref)
            continue
        asset_id = run_db(lambda s, e=external_ref, d=full_ref: upsert_asset(
            s, type="image", source="source_connection", external_ref=e, display_name=d,
        ))
        try:
            upsert_sbom(org, full_ref, digest, sbom, run_id, asset_id=asset_id)
            assets[asset_id] = external_ref
        except Exception:
            logger.warning("Failed to ingest SBOM for image %s", full_ref)
    return assets


def ingest_container_from_minio(org: str, run_id: str, source_type: str | None = None) -> int:
    """Ingest a container scan: index image SBOMs and match their components
    against the OSV mirror to produce findings.

    The runner uploads only SBOMs; vulnerability matching happens here. Returns
    the finding count.
    """
    from src.db.helpers import run_db
    from src.osv.sca_findings import build_backend_match_findings

    if not source_type:
        logger.error(
            "container ingest for %s/%s has no source_type; cannot resolve assets", org, run_id
        )
        update_container_scanning_run(org, run_id, {
            "status": "failed", "finishedAt": now_iso(),
            "error": "missing source_type for OSV matching",
        })
        return 0

    prefix = f"container_scanning/{org}/{run_id}/"
    assets = _index_container_sboms(org, run_id, source_type, prefix)

    async def _match(session) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for asset_id, external_ref in assets.items():
            out.extend(await build_backend_match_findings(
                session, asset_id=asset_id, external_ref=external_ref, kind="container",
                match_source="scan",
            ))
        return out

    findings: list[dict[str, Any]] = run_db(_match) if assets else []

    config = get_container_scanner_config()
    nvd_enabled = config.get("nvdEnabled") in (True, "true")
    nvd_api_key = config.get("nvdApiKey", "")
    ghsa_enabled = config.get("ghsaEnabled") in (True, "true")
    ghsa_api_key = config.get("ghsaApiKey", "")

    if findings and (nvd_enabled or ghsa_enabled):
        # Isolate enrichment failures so an NVD/GHSA outage degrades gracefully
        # instead of failing the whole container ingest (matches the deps path).
        try:
            findings = enrich_findings_with_advisory_data(
                findings,
                nvd_enabled=nvd_enabled,
                nvd_api_key=nvd_api_key,
                ghsa_enabled=ghsa_enabled,
                ghsa_api_key=ghsa_api_key,
            )
        except Exception:
            logger.warning("Advisory enrichment failed for %s", org)

    if findings:
        ctx = ScanContext(
            tool="container_scanning",
            org=org,
            run_id=run_id,
            source_type=source_type,
        )
        new_findings = _apply_lifecycle(container_scanning_hooks, ctx, findings)

        if new_findings:
            try:
                from src.notifications.emitter import notify_new_critical_findings
                notify_new_critical_findings("container_scanning", org, new_findings)
            except Exception:
                logger.warning("Failed to emit new finding notifications", exc_info=True)

            from src.shared.event_emit_helpers import emit_finding_created
            for finding in new_findings:
                emit_finding_created(
                    finding=finding,
                    scanner_type="containers",
                    source_component="containers.scanner",
                )

    logger.info(
        "Ingested %d container findings for org=%s run=%s",
        len(findings),
        org,
        run_id,
    )

    # Guard against race: don't overwrite a concurrent cancellation
    from src.storage import list_container_scanning_runs
    current = next((r for r in list_container_scanning_runs(org) if r.get("id") == run_id), None)
    if current and current.get("status") == "cancelled":
        logger.info("Skipping completion — run %s already cancelled", run_id)
        return len(findings)

    update_container_scanning_run(org, run_id, {
        "status": "completed",
        "finishedAt": now_iso(),
        "findingsCount": len(findings),
        "progress": {"percent": 100, "stage": "completed"},
    })

    return len(findings)


def execute_container_scan_once(
    org: str,
    token: str | None,
    run_id: str,
    *,
    source_type: str | None = None,
    scanner_config: dict[str, Any] | None = None,
    mode: str = "full",
    scan_mode: str = "full",
    runtime: Any = None,
) -> None:
    """Execute a container scan for one org."""
    config = scanner_config or get_container_scanner_config()
    runtime_started = runtime.start(org, run_id) if runtime else False
    if runtime and not runtime_started:
        return

    update_container_scanning_run(org, run_id, {
        "startedAt": now_iso(),
        "progress": {"percent": 0, "stage": "queued"},
    })

    try:
        _run_full_or_sbom(org, run_id, config, scan_mode, runtime, source_type=source_type)

        if runtime and runtime.is_cancelled(run_id):
            return

        # Final status set by ingest_container_from_minio on runner callback

    except Exception as exc:
        logger.exception("Container scan failed: org=%s run=%s", org, run_id)
        update_container_scanning_run(org, run_id, {
            "status": "failed",
            "finishedAt": now_iso(),
            "error": str(exc),
            "progress": {"percent": 0, "stage": "failed"},
        })
    finally:
        if runtime and runtime_started:
            runtime.release(org)


def _run_full_or_sbom(
    org: str,
    run_id: str,
    config: dict[str, Any],
    scan_mode: str,
    runtime: Any,
    source_type: str | None = None,
) -> None:
    """Run full or sbom_only scan via runner."""
    sources = get_scan_sources_for_org(org)
    all_images: list[str] = []
    registry_auths: list[dict[str, str]] = []
    seen_registries: set[str] = set()
    for src in sources:
        images = getattr(src, "container_images", []) or []
        all_images.extend(images)
        token = getattr(src, "registry_token", "") or ""
        if not token:
            continue
        for img in images:
            parts = img.split("/")
            registry = parts[0] if len(parts) > 1 and "." in parts[0] else ""
            if registry and registry not in seen_registries:
                seen_registries.add(registry)
                username = getattr(src, "registry_username", "") or ""
                if not username:
                    username = _resolve_registry_username(registry, token)
                registry_auths.append({
                    "registry": registry,
                    "username": username,
                    "token": token,
                })

    if not all_images:
        raise ValueError(f"No container images configured for org {org}")

    docker_images = ",".join(all_images)

    prev_digests = _get_previous_digests(org)
    update_container_scanning_run(org, run_id, {
        "progress": {
            "percent": 0,
            "stage": "queued",
            "expectedRepos": len(all_images),
            "scannedRepos": 0,
        },
    })

    result = _execute_via_runner(org, run_id, config, docker_images, scan_mode, registry_auths=registry_auths, prev_digests=prev_digests, source_type=source_type)
    if not result or result.get("status") in ("failed", "cancelled"):
        if result and result.get("status") == "cancelled":
            return  # Cancelled — don't raise, let is_cancelled() handle it
        raise RuntimeError(
            f"Runner job failed: {result.get('error', 'unknown') if result else 'no result'}"
        )


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


_container_scanning_runtime = InMemoryScanRuntime()

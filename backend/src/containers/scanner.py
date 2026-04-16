"""Container Scanner — Syft + Grype orchestration via runner service."""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Literal

from src.containers.lifecycle import container_scanning_hooks
from src.containers.sbom_store import upsert_sbom, list_stored_sboms
from src.shared.config import get_container_scanner_config, get_scan_sources_for_org
from src.shared.enrichment import ingest_findings_jsonl, enrich_findings_with_advisory_data
from src.shared.lifecycle import ScanContext, apply_lifecycle as _apply_lifecycle
from src.shared.paths import DATA_DIR
from src.storage import (
    update_container_scanning_run,
)

logger = logging.getLogger(__name__)

CONTAINER_SCANNER_IMAGE = "aegis/scanner-container:latest"
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

    # advisories_only needs S3 read access to download stored SBOMs
    if scan_mode == "advisories_only":
        env_vars["S3_ENDPOINT"] = os.getenv("S3_ENDPOINT", "")
        env_vars["S3_ACCESS_KEY"] = os.getenv("S3_ACCESS_KEY", "")
        env_vars["S3_SECRET_KEY"] = os.getenv("S3_SECRET_KEY", "")
        env_vars["S3_BUCKET"] = "sboms"

    image = config.get("dockerImage") or config.get("image") or CONTAINER_SCANNER_IMAGE
    job = create_job(
        job_type="container_scanning",
        org=org,
        run_id=run_id,
        docker_image=image,
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
    org: str, run_id: str
) -> dict[str, dict[str, Any]]:
    """Download SBOMs from object store. Returns {image_name: {sbom, digest}}."""
    from src.shared.object_store import list_objects, download_json, download_bytes

    prefix = f"container_scanning/{org}/{run_id}/"
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


def _fallback_ingest_per_image(org: str, run_id: str, prefix: str) -> list[dict[str, Any]]:
    """Fallback: normalize per-image findings.json when findings.jsonl is missing."""
    from src.shared.object_store import list_objects, download_bytes, download_json

    keys = list_objects(prefix)
    findings: list[dict[str, Any]] = []

    image_dirs: dict[str, dict[str, str]] = {}
    for key in keys:
        rel = key[len(prefix):]
        parts = rel.split("/")
        if len(parts) < 2:
            continue
        image_dir = parts[0]
        filename = parts[1]
        image_dirs.setdefault(image_dir, {})[filename] = key

    for image_dir, files in image_dirs.items():
        if "findings.json" not in files or "sbom.cdx.json" not in files:
            continue
        grype_data = download_json(files["findings.json"])
        if not grype_data:
            continue
        sbom_data = download_json(files["sbom.cdx.json"])
        image_ref = (sbom_data or {}).get("metadata", {}).get("component", {}).get("name", image_dir.replace("_", "/"))
        digest_blob = download_bytes(files["digest.txt"]) if "digest.txt" in files else None
        image_digest = digest_blob.decode().strip() if digest_blob else ""

        if ":" in image_ref and not image_ref.startswith("sha256:"):
            image_name, image_tag = image_ref.rsplit(":", 1)
        else:
            image_name, image_tag = image_ref, "latest"

        for match in grype_data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            fix = vuln.get("fix", {})
            vid = vuln.get("id", "")
            ghsa_id = vid if vid.startswith("GHSA-") else next((r["id"] for r in match.get("relatedVulnerabilities", []) if r.get("id", "").startswith("GHSA-")), None)
            cve_id = vid if vid.startswith("CVE-") else next((r["id"] for r in match.get("relatedVulnerabilities", []) if r.get("id", "").startswith("CVE-")), None)
            fix_versions = fix.get("versions", [])
            locations = artifact.get("locations", [])

            findings.append({
                "organization": org,
                "repository": image_name,
                "source": "container",
                "commitSha": image_digest,
                "packageName": artifact.get("name", ""),
                "packageVersion": artifact.get("version", ""),
                "manifestPath": locations[0].get("path", "") if locations else "",
                "ecosystem": artifact.get("type", ""),
                "advisoryId": ghsa_id or cve_id or vid,
                "ghsaId": ghsa_id,
                "cveId": cve_id,
                "severity": (vuln.get("severity") or "unknown").lower(),
                "fixedVersion": fix_versions[0] if fix_versions else None,
                "fixState": fix.get("state", "unknown"),
                "summary": (vuln.get("description") or "")[:200],
                "description": vuln.get("description", ""),
                "scanner": "grype",
                "stateCandidate": "open",
                "imageName": image_name,
                "imageTag": image_tag,
                "imageDigest": image_digest,
            })

    if findings:
        logger.info("Fallback: normalized %d findings from %d per-image files", len(findings), len(image_dirs))
    return findings


def ingest_container_from_minio(org: str, run_id: str) -> int:
    """Ingest scan results from object store after runner completion. Returns finding count."""
    from src.shared.object_store import find_findings_jsonl

    config = get_container_scanner_config()
    prefix = f"container_scanning/{org}/{run_id}/"

    findings = []
    blob = find_findings_jsonl(prefix)
    if blob:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".jsonl", delete=False) as f:
            f.write(blob)
            tmp_path = f.name
        from pathlib import Path
        findings = ingest_findings_jsonl(org, run_id, Path(tmp_path))
        os.unlink(tmp_path)
    elif blob is None:
        findings = _fallback_ingest_per_image(org, run_id, prefix)
        if not findings:
            logger.warning("No findings.jsonl found under %s", prefix)

    image_sboms = _download_scan_output_from_minio(org, run_id)
    for image_safe_name, data in image_sboms.items():
        sbom = data.get("sbom")
        if not sbom:
            continue
        metadata = sbom.get("metadata", {})
        component = metadata.get("component", {})
        image_ref = component.get("name", image_safe_name.replace("_", "/"))
        digest = data.get("digest")
        upsert_sbom(org, image_ref, digest, sbom, run_id)

    nvd_enabled = config.get("nvdEnabled") in (True, "true")
    nvd_api_key = config.get("nvdApiKey", "")
    ghsa_enabled = config.get("ghsaEnabled") in (True, "true")
    ghsa_api_key = config.get("ghsaApiKey", "")

    if findings and (nvd_enabled or ghsa_enabled):
        findings = enrich_findings_with_advisory_data(
            findings,
            nvd_enabled=nvd_enabled,
            nvd_api_key=nvd_api_key,
            ghsa_enabled=ghsa_enabled,
            ghsa_api_key=ghsa_api_key,
        )

    if findings:
        ctx = ScanContext(
            tool="container_scanning",
            org=org,
            run_id=run_id,
        )
        new_findings = _apply_lifecycle(container_scanning_hooks, ctx, findings)

        if new_findings:
            try:
                from src.notifications.emitter import notify_new_critical_findings
                notify_new_critical_findings("container_scanning", org, new_findings)
            except Exception:
                logger.warning("Failed to emit new finding notifications", exc_info=True)

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
        if scan_mode == "advisories_only":
            _run_advisories_only(org, run_id, config)
        else:
            _run_full_or_sbom(org, run_id, config, scan_mode, runtime)

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

    import json as _json
    prev_digests = _get_previous_digests(org)
    update_container_scanning_run(org, run_id, {
        "progress": {
            "percent": 0,
            "stage": "queued",
            "expectedRepos": len(all_images),
            "scannedRepos": 0,
        },
    })

    result = _execute_via_runner(org, run_id, config, docker_images, scan_mode, registry_auths=registry_auths, prev_digests=prev_digests)
    if not result or result.get("status") in ("failed", "cancelled"):
        if result and result.get("status") == "cancelled":
            return  # Cancelled — don't raise, let is_cancelled() handle it
        raise RuntimeError(
            f"Runner job failed: {result.get('error', 'unknown') if result else 'no result'}"
        )


def _run_advisories_only(
    org: str,
    run_id: str,
    config: dict[str, Any],
) -> None:
    """Re-match stored SBOMs against updated advisory databases."""
    stored = list_stored_sboms(org)

    if not stored:
        raise ValueError(f"No stored SBOMs found for org {org}")

    image_refs = [s["repo"] for s in stored]
    docker_images = ",".join(image_refs)

    result = _execute_via_runner(org, run_id, config, docker_images, "advisories_only")
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

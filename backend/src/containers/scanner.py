"""Container Scanner — the runner generates a Syft SBOM; the backend matches it
against the OSV mirror. No vulnerability matcher runs on the runner."""
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
from src.releases.enrichment import maybe_enrich_release_age
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

    # Opt-in: have the runner list registry tags so ingest can recommend newer ones.
    if config.get("baseImageTagsEnabled") in (True, "true"):
        env_vars["CONTAINER_LIST_TAGS"] = "true"

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
            image_sboms[image_safe_name] = {"sbom": None, "digest": None, "tags": None}

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

        elif filename == "tags.json":
            tags_doc = download_json(key)
            if isinstance(tags_doc, dict):
                image_sboms[image_safe_name]["tags"] = tags_doc.get("tags")

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


def _index_container_sboms(
    org: str, run_id: str, source_type: str, prefix: str
) -> tuple[dict[str, str], dict[str, list[str]], dict[str, dict[str, Any]]]:
    """Index each image SBOM under its resolved image asset.

    Returns ({asset_id: external_ref}, {asset_id: newer_tags}, {asset_id: meta})
    for the images indexed this run — the first so the caller can match
    components against the OSV mirror, the second to surface newer available
    registry tags, the third (``pullable_ref``/``digest``/``sbom``) so the
    base-image recommendation can rescan candidates and count against the
    current image's own SBOM. The tag/meta maps are empty unless the opt-in tag
    listing ran and found strictly-newer same-flavour tags.
    """
    from src.assets.service import upsert_asset
    from src.db.helpers import run_db
    from src.containers.tag_recommendation import select_newer_tags

    assets: dict[str, str] = {}
    newer_by_asset: dict[str, list[str]] = {}
    meta_by_asset: dict[str, dict[str, Any]] = {}
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
        # Display the canonical registry-prefixed ref (e.g. "ghcr:acme/app:1.2.3")
        # so image assets read the same way as repos ("github:acme/repo") — and so
        # a clean (no-finding) image doesn't get stuck at the bare SBOM component
        # name that the findings-lifecycle writer would otherwise overwrite.
        asset_id = run_db(lambda s, e=external_ref: upsert_asset(
            s, type="image", source="source_connection", external_ref=e, display_name=e,
        ))
        try:
            upsert_sbom(org, full_ref, digest, sbom, run_id, asset_id=asset_id)
            assets[asset_id] = external_ref
            raw_tags = data.get("tags")
            if isinstance(raw_tags, list) and raw_tags:
                # Current tag is the last ":"-segment of the image ref.
                current_tag = full_ref.rpartition(":")[2] if ":" in full_ref else None
                newer = select_newer_tags(current_tag, raw_tags)
                if newer:
                    newer_by_asset[asset_id] = newer
                    meta_by_asset[asset_id] = {
                        "pullable_ref": full_ref, "digest": digest, "sbom": sbom,
                    }
        except Exception:
            logger.warning("Failed to ingest SBOM for image %s", full_ref)
    return assets, newer_by_asset, meta_by_asset


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
    assets, newer_by_asset, meta_by_asset = _index_container_sboms(
        org, run_id, source_type, prefix
    )

    async def _match(session) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for asset_id, external_ref in assets.items():
            asset_findings = await build_backend_match_findings(
                session, asset_id=asset_id, external_ref=external_ref, kind="container",
                match_source="scan",
            )
            newer = newer_by_asset.get(asset_id)
            if newer:
                for f in asset_findings:
                    f["newerTags"] = newer
            out.extend(asset_findings)
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

    maybe_enrich_release_age(findings, config, org)

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

    # Opt-in: prove a newer base tag has fewer vulns by rescanning candidates.
    # Never runs for a candidate (reco-) scan's own ingest — those don't reach
    # here (the runner callback skips ingest for reco- runs).
    if (
        not run_id.startswith("reco-")
        and config.get("baseImageRecommendEnabled") in (True, "true")
        and meta_by_asset
    ):
        try:
            _recommend_base_images(org, config, source_type, meta_by_asset, newer_by_asset)
        except Exception:
            logger.warning("Base-image recommendation failed for %s", org, exc_info=True)

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


def _gather_images_and_auths(org: str) -> tuple[list[str], list[dict[str, str]]]:
    """Collect the org's configured container images and per-registry pull auth."""
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
                registry_auths.append(
                    {"registry": registry, "username": username, "token": token}
                )
    return all_images, registry_auths


def _scan_candidate_sbom(
    org: str,
    config: dict[str, str],
    candidate_ref: str,
    registry_auths: list[dict[str, str]],
    source_type: str | None,
) -> dict | None:
    """SBOM-scan one candidate image ref and return its CycloneDX SBOM.

    Uses a ``reco-`` run id so the runner completion callback skips the normal
    ingest — the SBOM is consumed here for counting, never persisted as findings.
    Returns None on any failure (image gone, auth, timeout) — a soft skip."""
    from uuid import uuid4

    candidate_run_id = f"reco-{uuid4().hex[:12]}"
    # Don't re-list tags or recurse on the candidate scan.
    cand_config = {
        **config, "baseImageTagsEnabled": "false", "baseImageRecommendEnabled": "false",
    }
    result = _execute_via_runner(
        org, candidate_run_id, cand_config, docker_images=candidate_ref,
        scan_mode="sbom_only", registry_auths=registry_auths, source_type=source_type,
    )
    if not result:
        return None
    prefix = f"container_scanning/{org}/{candidate_run_id}/"
    for data in _download_scan_output_from_minio(org, candidate_run_id, prefix).values():
        if data.get("sbom"):
            return data["sbom"]
    return None


def _recommend_base_images(
    org: str,
    config: dict[str, str],
    source_type: str | None,
    meta_by_asset: dict[str, dict[str, Any]],
    newer_by_asset: dict[str, list[str]],
) -> None:
    """Scan the top newer candidate per image and store the better base tag.

    Counts current and candidate vulnerabilities identically (in memory against
    the OSV mirror) so the delta is honest, and records the result — including a
    "nothing improves" negative — keyed by the current image digest.
    """
    from datetime import datetime, timezone
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from src.db.helpers import run_db
    from src.db.models import BaseImageRecommendation
    from src.containers.base_image_reco import (
        build_candidate_ref, count_sbom_vulns, pick_recommendation,
    )

    _, registry_auths = _gather_images_and_auths(org)

    for asset_id, meta in meta_by_asset.items():
        newer = newer_by_asset.get(asset_id) or []
        digest = meta.get("digest")
        current_sbom = meta.get("sbom")
        pullable_ref = meta.get("pullable_ref")
        if not (newer and digest and current_sbom and pullable_ref):
            continue

        top_tag = newer[0]
        candidate_ref = build_candidate_ref(pullable_ref, top_tag)
        candidate_sbom = _scan_candidate_sbom(
            org, config, candidate_ref, registry_auths, source_type
        )
        if candidate_sbom is None:
            continue

        async def _count(session, cur=current_sbom, cand=candidate_sbom):
            return (
                await count_sbom_vulns(session, cur),
                await count_sbom_vulns(session, cand),
            )

        current_count, candidate_count = run_db(_count)
        reco = pick_recommendation(current_count, {top_tag: candidate_count})

        async def _store(session, d=digest, ref=pullable_ref, cc=current_count, r=reco):
            values = {
                "image_digest": d,
                "current_ref": ref,
                "current_vuln_count": cc,
                "recommended_tag": r[0] if r else None,
                "recommended_vuln_count": r[1] if r else None,
                "candidates_scanned": 1,
                "computed_at": datetime.now(timezone.utc),
            }
            stmt = (
                pg_insert(BaseImageRecommendation)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=["image_digest"],
                    set_={k: v for k, v in values.items() if k != "image_digest"},
                )
            )
            await session.execute(stmt)
            await session.commit()

        run_db(_store)


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
    all_images, registry_auths = _gather_images_and_auths(org)

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

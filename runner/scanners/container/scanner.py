"""ContainerScanner — per-image syft SBOM build + register.

Orchestrates per-image syft (SBOM) generation, registers the SBOM (and a
digest marker) for upload, then writes the _done manifest marker. Vulnerability
matching happens in the backend against the OSV mirror — the runner produces
SBOMs only.

``PREVIOUS_DIGESTS`` is honoured to skip images whose registry manifest digest
has not changed since the last run. Private registry auth is configured up-front
from the REGISTRY_AUTHS env var.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import json
import logging
import os
import re
import shutil
import threading
from pathlib import Path
from typing import Any, Callable

from runner.scanners._manifest import write_done_marker
from runner.scanners._shared import (
    BaseScanConfig,
    JobEnv,
    ProgressEmitter,
    ScannerConfigError,
    TIMEOUT_SYFT_IMAGE,
    log_finished,
    log_scanning_image,
    parse_repos,
    register_output,
)
from runner.scanners._subprocess import (
    CANCELLED_EXIT_CODE,
    ScannerTimeoutError,
    run_tool,
)
from runner.scanners.base import ExecutionResult
from runner.scanners.container import (
    digest_compare,
    registry_auth,
    registry_digest,
)

logger = logging.getLogger(__name__)


# Mirrors bash validate_image_ref regex: ^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$
_VALID_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
# Mirrors bash sanitize_name: s/[^a-zA-Z0-9._-]/_/g
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")

SCAN_MODE_FULL = "full"
SCAN_MODE_SBOM_ONLY = "sbom_only"
SUPPORTED_SCAN_MODES = {
    SCAN_MODE_FULL,
    SCAN_MODE_SBOM_ONLY,
}
DEFERRED_SCAN_MODES: set[str] = set()
_UNSUPPORTED_MODE_EXIT_CODE = 2


@dataclasses.dataclass(frozen=True)
class ContainerScanConfig(BaseScanConfig):
    images: list[str]
    scan_mode: str
    scan_platform: str
    previous_digests_raw: str

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "ContainerScanConfig":
        env = JobEnv(job)
        scan_mode = env.get("SCAN_MODE", SCAN_MODE_FULL).lower()
        if scan_mode not in SUPPORTED_SCAN_MODES:
            raise ScannerConfigError(
                f"[!] SCAN_MODE={scan_mode!r} is not implemented in the "
                f"embedded scanner. Supported: {sorted(SUPPORTED_SCAN_MODES)}. "
                f"Deferred: {sorted(DEFERRED_SCAN_MODES)}."
            )
        return cls(
            org_label=env.get("ORG_LABEL", "default"),
            run_id=env.get("RUN_ID", str(job.get("jobId", "unknown"))),
            concurrency=max(1, env.get_int("CONCURRENCY", 4)),
            images=parse_repos(env.get("DOCKER_IMAGES")),
            scan_mode=scan_mode,
            scan_platform=env.get("SCAN_PLATFORM", "linux/amd64"),
            previous_digests_raw=env.get("PREVIOUS_DIGESTS", ""),
        )


class ContainerScanner:
    SCANNER_TYPE = "container_scanning"

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ExecutionResult:
        env_vars: dict[str, str] = job.get("envVars") or {}

        # registry_auth reads REGISTRY_AUTHS from os.environ — promote any
        # job-supplied value before configuration runs.
        if "REGISTRY_AUTHS" in env_vars and "REGISTRY_AUTHS" not in os.environ:
            os.environ["REGISTRY_AUTHS"] = env_vars["REGISTRY_AUTHS"]

        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        log_tail: list[str] = []

        try:
            cfg = ContainerScanConfig.from_job(job)
        except ScannerConfigError as exc:
            message = str(exc)
            logger.error(message)
            log_tail = [message]
            emitter = ProgressEmitter(on_progress, expected=0)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=_UNSUPPORTED_MODE_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail,
            )

        if "ORG_LABEL" not in os.environ:
            os.environ["ORG_LABEL"] = cfg.org_label

        raw_images = cfg.images
        images: list[str] = []
        for ref in raw_images:
            if _validate_image_ref(ref):
                images.append(ref)
            else:
                log_tail.append(f"[!] Invalid image reference: {ref}")

        previous_digests = digest_compare.parse_previous_digests(
            cfg.previous_digests_raw
        )
        if cfg.previous_digests_raw and not previous_digests:
            log_tail.append(
                "[!] PREVIOUS_DIGESTS could not be parsed — proceeding "
                "without skip-unchanged optimisation"
            )

        emitter = ProgressEmitter(on_progress, expected=len(images))

        if cancel_event is not None and cancel_event.is_set():
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=CANCELLED_EXIT_CODE, job_dir=out_dir, log_tail=log_tail
            )

        if not images:
            log_tail.append("[!] No valid images to scan")
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

        emitter.starting()

        try:
            count = registry_auth.configure_registry_auth()
            if count:
                logger.info("[+] Registry auth configured for %d registries", count)
        except Exception as e:  # noqa: BLE001
            logger.warning("[!] Registry auth setup failed: %s", e)

        def _scan_one(image_ref: str) -> Path | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            # Use the sanitized image name as the progress label, matching the
            # per-image output directory. Backend schema reuses the *Repos
            # counter names for container jobs.
            safe_name = _sanitize_name(image_ref)
            emitter.scanning(safe_name)
            try:
                return self._scan_image(
                    image_ref,
                    out_dir,
                    scan_platform=cfg.scan_platform,
                    cancel_event=cancel_event,
                    previous_digests=previous_digests,
                    log_tail=log_tail,
                )
            except ScannerTimeoutError as e:
                log_tail.append(f"[!] Timeout scanning {image_ref}: {e}")
                return None
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] Image {image_ref} failed: {e}")
                logger.exception("[!] Image %s failed", image_ref)
                return None
            finally:
                emitter.finished(safe_name)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=cfg.concurrency
        ) as pool:
            list(pool.map(_scan_one, images))

        emitter.normalizing()
        write_done_marker(out_dir)
        emitter.done()

        exit_code = 0
        if cancel_event is not None and cancel_event.is_set():
            exit_code = CANCELLED_EXIT_CODE
        return ExecutionResult(
            exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:]
        )

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _scan_image(
        self,
        image_ref: str,
        out_dir: Path,
        *,
        scan_platform: str,
        cancel_event: threading.Event | None,
        previous_digests: dict[str, str] | None = None,
        log_tail: list[str] | None = None,
    ) -> Path | None:
        safe_name = _sanitize_name(image_ref)
        image_out = out_dir / safe_name
        image_out.mkdir(parents=True, exist_ok=True)
        log_scanning_image(image_ref)

        # Skip-unchanged optimisation — compare the registry HEAD digest
        # against the backend-supplied previous digest *before* running syft,
        # avoiding the expensive image pull when nothing changed.
        prev = (
            digest_compare.lookup_previous_digest(image_ref, previous_digests)
            if previous_digests
            else None
        )
        if prev:
            current = registry_digest.fetch_registry_digest(
                image_ref, cancel_event=cancel_event
            )
            if current and digest_compare.digests_match(current, prev):
                self._record_skipped_image(
                    image_ref=image_ref,
                    image_out=image_out,
                    out_dir=out_dir,
                    safe_name=safe_name,
                    digest=current,
                    log_tail=log_tail,
                )
                return None

        sbom_path = image_out / "sbom.cdx.json"
        syft_json_path = image_out / "sbom.syft.json"
        if not self._run_syft(
            image_ref,
            scan_platform,
            sbom_path,
            cancel_event,
            syft_json_output=syft_json_path,
        ):
            log_finished(image_ref)
            return None

        register_output(out_dir, sbom_path, safe_name)
        if syft_json_path.exists() and syft_json_path.stat().st_size > 0:
            register_output(out_dir, syft_json_path, safe_name)

        # Prefer the SBOM hash. Fall back to a registry HEAD digest so backend
        # dedup (which keys on imageDigest) keeps working when some registries
        # don't surface SHA-256 hashes via syft.
        digest = _read_sbom_sha256(sbom_path)
        if digest:
            (image_out / "digest.txt").write_text(f"sha256:{digest}")
            register_output(out_dir, image_out / "digest.txt", safe_name)
        else:
            fallback = registry_digest.fetch_registry_digest(
                image_ref, cancel_event=cancel_event
            )
            if fallback:
                (image_out / "digest.txt").write_text(fallback)
                register_output(out_dir, image_out / "digest.txt", safe_name)

        log_finished(image_ref)
        return sbom_path

    def _record_skipped_image(
        self,
        *,
        image_ref: str,
        image_out: Path,
        out_dir: Path,
        safe_name: str,
        digest: str,
        log_tail: list[str] | None,
    ) -> None:
        """Persist the digest marker for an unchanged image and emit progress.

        Backend dedup pairs findings with ``imageDigest``; even though no new
        SBOM is produced this run, digest.txt must still exist (and appear in
        the manifest) so the agent reports the image as scanned and so any
        subsequent ``PREVIOUS_DIGESTS`` payload still includes it.
        """
        normalized = digest_compare.normalize_digest(digest) or ""
        marker = f"sha256:{normalized}" if normalized else digest
        (image_out / "digest.txt").write_text(marker)
        register_output(out_dir, image_out / "digest.txt", safe_name)
        message = f"[=] Skipping unchanged image: {image_ref} (digest {marker})"
        print(message, flush=True)
        logger.info(message)
        if log_tail is not None:
            log_tail.append(message)
        log_finished(image_ref)

    def _run_syft(
        self,
        image_ref: str,
        scan_platform: str,
        output: Path,
        cancel_event: threading.Event | None,
        syft_json_output: Path | None = None,
    ) -> bool:
        if shutil.which("syft") is None:
            logger.warning("[!] syft not on PATH - skipping %s", image_ref)
            return False
        cmd = [
            "syft",
            f"registry:{image_ref}",
            "--platform",
            scan_platform,
            "-o",
            "cyclonedx-json",
        ]
        # syft-json carries source.metadata (imageSize, layers, os) which Syft
        # already collected for the registry pull — getting it as a sidecar
        # avoids a second registry round-trip in the backend.
        if syft_json_output is not None:
            cmd += ["-o", f"syft-json={syft_json_output}"]
        cmd += ["--parallelism", "2"]
        rc, stdout, stderr = run_tool(
            cmd,
            timeout=TIMEOUT_SYFT_IMAGE,
            cancel_event=cancel_event,
        )
        if rc != 0:
            logger.warning(
                "[!] Syft failed for %s: %s", image_ref, (stderr or "")[:200]
            )
            return False
        output.write_text(stdout)
        return output.exists() and output.stat().st_size > 0


def _validate_image_ref(ref: str) -> bool:
    """Return True if ref looks like a safe image reference.

    Mirrors the bash ``validate_image_ref`` function: requires the first char to
    be alphanumeric, then alphanumerics plus ``._/:@-``."""
    if not ref:
        return False
    return bool(_VALID_IMAGE_REF.match(ref))


def _sanitize_name(image_ref: str) -> str:
    """Map an image reference to a filesystem-safe directory name.

    Mirrors bash ``sanitize_name``: replaces any character not in
    ``[a-zA-Z0-9._-]`` with ``_``."""
    return _SAFE_NAME_RE.sub("_", image_ref)


def _read_sbom_sha256(sbom_path: Path) -> str | None:
    """Return the SHA-256 hash from a CycloneDX SBOM's metadata.component.hashes.

    Mirrors the jq filter in run.sh::

        .metadata.component.hashes // []
          | map(select(.alg == "SHA-256")) | .[0].content
    """
    try:
        data = json.loads(sbom_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    hashes = (
        ((data.get("metadata") or {}).get("component") or {}).get("hashes") or []
    )
    for h in hashes:
        if h.get("alg") == "SHA-256":
            content = h.get("content")
            if isinstance(content, str) and content:
                return content
    return None

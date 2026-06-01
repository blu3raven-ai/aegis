"""ContainerScanner — embedded port of scanners/container/run.sh.

Orchestrates per-image syft (SBOM) -> grype match -> normalize, then aggregates
findings.jsonl and writes the _done manifest marker. Supports two scan modes:

* ``full`` (default) — pull image with syft, build SBOM, run grype. Honours
  ``PREVIOUS_DIGESTS`` to skip images whose registry manifest digest has not
  changed since the last run.
* ``advisories_only`` — re-run grype against previously stored SBOMs from
  MinIO without re-pulling images. Used by the backend to refresh advisory
  matches after a new vuln-DB update.

Private registry auth is configured up-front from the REGISTRY_AUTHS env var.
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
import shutil
import threading
from pathlib import Path
from typing import Callable

from runner.scanners._manifest import write_done_marker
from runner.scanners._shared import (
    ProgressEmitter,
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
    download_sbom,
    normalize,
    registry_auth,
    registry_digest,
)

logger = logging.getLogger(__name__)


_GRYPE_DB_CHECK_TIMEOUT_S = 60.0
_GRYPE_DB_UPDATE_TIMEOUT_S = 600.0
_GRYPE_MATCH_TIMEOUT_S = 300.0
_SYFT_TIMEOUT_S = 900.0

_GRYPE_VULNS_FOUND_RC = 1  # grype convention — not an error

# Mirrors bash validate_image_ref regex: ^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$
_VALID_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
# Mirrors bash sanitize_name: s/[^a-zA-Z0-9._-]/_/g
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")

SCAN_MODE_FULL = "full"
SCAN_MODE_ADVISORIES_ONLY = "advisories_only"
SCAN_MODE_SBOM_ONLY = "sbom_only"
SUPPORTED_SCAN_MODES = {
    SCAN_MODE_FULL,
    SCAN_MODE_ADVISORIES_ONLY,
    SCAN_MODE_SBOM_ONLY,
}
DEFERRED_SCAN_MODES: set[str] = set()
_UNSUPPORTED_MODE_EXIT_CODE = 2


class ContainerScanner:
    SCANNER_TYPE = "container"

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ExecutionResult:
        env_vars: dict[str, str] = (
            (job.get("dockerArgs") or {}).get("envVars") or {}
        )
        images_input = (
            env_vars.get("DOCKER_IMAGES") or os.environ.get("DOCKER_IMAGES", "")
        )
        org_label = (
            env_vars.get("ORG_LABEL") or os.environ.get("ORG_LABEL") or "default"
        )
        scan_platform = (
            env_vars.get("SCAN_PLATFORM")
            or os.environ.get("SCAN_PLATFORM")
            or "linux/amd64"
        )
        scan_mode = (
            env_vars.get("SCAN_MODE")
            or os.environ.get("SCAN_MODE")
            or SCAN_MODE_FULL
        ).lower()
        previous_digests_raw = (
            env_vars.get("PREVIOUS_DIGESTS")
            or os.environ.get("PREVIOUS_DIGESTS")
            or ""
        )
        try:
            concurrency = int(
                env_vars.get("CONCURRENCY") or os.environ.get("CONCURRENCY") or "4"
            )
        except ValueError:
            concurrency = 4
        if concurrency < 1:
            concurrency = 1

        # registry_auth reads REGISTRY_AUTHS from os.environ — promote any
        # job-supplied value before configuration runs.
        if "REGISTRY_AUTHS" in env_vars and "REGISTRY_AUTHS" not in os.environ:
            os.environ["REGISTRY_AUTHS"] = env_vars["REGISTRY_AUTHS"]

        # advisories_only needs S3 creds in os.environ to reach MinIO.
        for var in (
            "S3_ENDPOINT",
            "S3_ACCESS_KEY",
            "S3_SECRET_KEY",
            "S3_REGION",
            "S3_BUCKET",
        ):
            if var in env_vars and var not in os.environ:
                os.environ[var] = env_vars[var]
        if "ORG_LABEL" not in os.environ:
            os.environ["ORG_LABEL"] = org_label

        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        log_tail: list[str] = []

        if scan_mode not in SUPPORTED_SCAN_MODES:
            message = (
                f"[!] SCAN_MODE={scan_mode!r} is not implemented in the "
                f"embedded scanner. Supported: {sorted(SUPPORTED_SCAN_MODES)}. "
                f"Deferred: {sorted(DEFERRED_SCAN_MODES)}."
            )
            logger.error(message)
            log_tail.append(message)
            emitter = ProgressEmitter(on_progress, expected=0)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=_UNSUPPORTED_MODE_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail,
            )

        raw_images = parse_repos(images_input)
        images: list[str] = []
        for ref in raw_images:
            if _validate_image_ref(ref):
                images.append(ref)
            else:
                log_tail.append(f"[!] Invalid image reference: {ref}")

        previous_digests = digest_compare.parse_previous_digests(
            previous_digests_raw
        )
        if previous_digests_raw and not previous_digests:
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

        self._ensure_grype_db(cancel_event)

        skip_grype = scan_mode == SCAN_MODE_SBOM_ONLY

        def _scan_one(image_ref: str) -> Path | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            # Use the sanitized image name as the progress label, matching the
            # per-image output directory. Backend schema reuses the *Repos
            # counter names for container jobs.
            safe_name = _sanitize_name(image_ref)
            emitter.scanning(safe_name)
            try:
                if scan_mode == SCAN_MODE_ADVISORIES_ONLY:
                    return self._scan_image_advisories_only(
                        image_ref,
                        out_dir,
                        cancel_event=cancel_event,
                        log_tail=log_tail,
                    )
                return self._scan_image(
                    image_ref,
                    out_dir,
                    scan_platform=scan_platform,
                    cancel_event=cancel_event,
                    previous_digests=previous_digests,
                    log_tail=log_tail,
                    skip_grype=skip_grype,
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
            max_workers=concurrency
        ) as pool:
            list(pool.map(_scan_one, images))

        emitter.normalizing()

        # sbom_only produces no per-image findings.json, so normalization is
        # a no-op — skip it to match bash run.sh:322-335 (the loop is gated
        # on findings.json existing).
        if not skip_grype:
            try:
                total, errors = normalize.normalize_grype_output(org_label, out_dir)
                log_tail.append(
                    f"[+] Normalized {total} container findings ({errors} errors)"
                )
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] Normalization failed: {e}")
                logger.exception("[!] Normalization failed")

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

    def _ensure_grype_db(self, cancel_event: threading.Event | None) -> None:
        if shutil.which("grype") is None:
            logger.warning("[!] grype not on PATH - skipping DB check")
            return
        rc, _, _ = run_tool(
            ["grype", "db", "check"],
            timeout=_GRYPE_DB_CHECK_TIMEOUT_S,
            cancel_event=cancel_event,
        )
        if rc == 0:
            return
        logger.info("[+] Updating Grype vulnerability database...")
        rc, _, stderr = run_tool(
            ["grype", "db", "update"],
            timeout=_GRYPE_DB_UPDATE_TIMEOUT_S,
            cancel_event=cancel_event,
        )
        if rc != 0:
            logger.warning(
                "[!] Grype DB update failed - scanning may produce incomplete "
                "results: %s",
                (stderr or "")[:200],
            )

    def _scan_image(
        self,
        image_ref: str,
        out_dir: Path,
        *,
        scan_platform: str,
        cancel_event: threading.Event | None,
        previous_digests: dict[str, str] | None = None,
        log_tail: list[str] | None = None,
        skip_grype: bool = False,
    ) -> Path | None:
        safe_name = _sanitize_name(image_ref)
        image_out = out_dir / safe_name
        image_out.mkdir(parents=True, exist_ok=True)
        log_scanning_image(image_ref)

        # Skip-unchanged optimisation — compare the registry HEAD digest
        # against the backend-supplied previous digest *before* running syft.
        # Matches bash check_digest_changed which performs a HEAD against the
        # registry, avoiding the expensive image pull when nothing changed.
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
        if not self._run_syft(image_ref, scan_platform, sbom_path, cancel_event):
            log_finished(image_ref)
            return None

        register_output(out_dir, sbom_path, safe_name)

        # Bash run.sh:210-214 — sbom_only: register SBOM, log finished, return.
        # No grype, no findings.json, no digest.txt.
        if skip_grype:
            log_finished(image_ref)
            return None

        findings_json = image_out / "findings.json"
        self._run_grype(sbom_path, findings_json, cancel_event)

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

        if findings_json.exists():
            register_output(out_dir, findings_json, safe_name)

        log_finished(image_ref)
        return findings_json if findings_json.exists() else None

    def _scan_image_advisories_only(
        self,
        image_ref: str,
        out_dir: Path,
        *,
        cancel_event: threading.Event | None,
        log_tail: list[str],
    ) -> Path | None:
        """Run grype against a previously stored SBOM from MinIO.

        Mirrors bash ``scan_advisories_only``: no syft, no image pull. A
        missing SBOM logs loudly but the overall scan continues — matches
        bash's per-image error handling."""
        safe_name = _sanitize_name(image_ref)
        image_out = out_dir / safe_name
        image_out.mkdir(parents=True, exist_ok=True)
        log_scanning_image(image_ref)

        sbom_path = image_out / "sbom.cdx.json"
        try:
            download_sbom.download_sbom_for_image(image_ref, sbom_path)
        except download_sbom.SbomDownloadError as e:
            log_tail.append(f"[!] No stored SBOM for {image_ref}: {e}")
            logger.warning("[!] No stored SBOM for %s: %s", image_ref, e)
            log_finished(image_ref)
            return None

        register_output(out_dir, sbom_path, safe_name)

        findings_json = image_out / "findings.json"
        self._run_grype(sbom_path, findings_json, cancel_event)

        digest = _read_sbom_sha256(sbom_path)
        if digest:
            (image_out / "digest.txt").write_text(f"sha256:{digest}")
            register_output(out_dir, image_out / "digest.txt", safe_name)

        if findings_json.exists():
            register_output(out_dir, findings_json, safe_name)

        log_finished(image_ref)
        return findings_json if findings_json.exists() else None

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
        findings are produced this run, digest.txt must still exist (and
        appear in the manifest) so the agent reports the image as scanned and
        so any subsequent ``PREVIOUS_DIGESTS`` payload still includes it.
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
    ) -> bool:
        if shutil.which("syft") is None:
            logger.warning("[!] syft not on PATH - skipping %s", image_ref)
            return False
        rc, stdout, stderr = run_tool(
            [
                "syft",
                f"registry:{image_ref}",
                "--platform",
                scan_platform,
                "-o",
                "cyclonedx-json",
                "--parallelism",
                "2",
            ],
            timeout=_SYFT_TIMEOUT_S,
            cancel_event=cancel_event,
        )
        if rc != 0:
            logger.warning(
                "[!] Syft failed for %s: %s", image_ref, (stderr or "")[:200]
            )
            return False
        output.write_text(stdout)
        return output.exists() and output.stat().st_size > 0

    def _run_grype(
        self,
        sbom: Path,
        output: Path,
        cancel_event: threading.Event | None,
    ) -> bool:
        if shutil.which("grype") is None:
            return False
        rc, stdout, stderr = run_tool(
            ["grype", f"sbom:{sbom}", "-o", "json", "--quiet"],
            timeout=_GRYPE_MATCH_TIMEOUT_S,
            cancel_event=cancel_event,
        )
        if rc in (0, _GRYPE_VULNS_FOUND_RC):
            output.write_text(stdout)
            return True
        logger.warning(
            "[!] Grype failed (exit %d) for %s: %s",
            rc,
            sbom.name,
            (stderr or "")[:200],
        )
        return False


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

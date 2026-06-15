"""DependenciesScanner — embedded port of scanners/dependencies/run.sh.

Orchestrates: optional custom advisory DB build, then per-repo
clone -> SBOM (syft + optional cdxgen merge) -> grype match -> normalize.
Per-repo work runs through a ThreadPoolExecutor; the resulting per-repo
findings.json files are aggregated into findings.jsonl, then the _done
manifest marker is written.

Two scan modes:

* ``full`` (default) — clone each repo, build SBOMs, run grype, normalize.
* ``advisories_only`` — skip the clone + SBOM build step and re-run grype
  against SBOMs previously stored in MinIO. Used by the backend to refresh
  advisory matches after a vuln-DB update without re-cloning every repo.

Grype DB precedence (matches bash run.sh): Argus paid-tier DB (if
``ARGUS_API_KEY`` + ``ARGUS_ENDPOINT`` set) > vunnel-built custom DB
(if ``ADVISORY_PROVIDERS`` set) > Grype's built-in DB.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import json
import logging
import os
import shutil
import threading
from pathlib import Path
from typing import Any, Callable

from runner.scanners._manifest import write_done_marker
from runner.scanners._shared import (
    BaseScanConfig,
    GitCloneError,
    InsecureURLError,
    JobEnv,
    ProgressEmitter,
    ScannerConfigError,
    TIMEOUT_CDXGEN,
    TIMEOUT_CLONE,
    TIMEOUT_GRYPE_DB_CHECK,
    TIMEOUT_GRYPE_DB_UPDATE,
    TIMEOUT_GRYPE_MATCH,
    TIMEOUT_SYFT_REPO,
    clone_repo,
    log_finished,
    log_scanning,
    parse_repos,
    register_output,
    repo_name_from_url,
)
from runner.scanners._subprocess import (
    CANCELLED_EXIT_CODE,
    ScannerTimeoutError,
    run_tool,
)
from runner.scanners.base import ExecutionResult
from runner.scanners.dependencies import (
    advisory_db,
    argus_db,
    download_sboms,
    normalize,
)
from runner.verification.budget import ScanBudget, make_sca_budget
from runner.verification.helpers.import_sites import find_import_sites
from runner.verification.helpers.prefilter import prefilter_sca_finding
from runner.verification.verifiers.sca import verify_sca_finding

logger = logging.getLogger(__name__)


_MIN_VERIFY_SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _build_llm_client():
    """Return an LLM client or None when LLM_API_KEY is unset."""
    from runner.verification.llm_client import LlmClient

    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        return None
    return LlmClient(
        api_key=api_key,
        api_base_url=os.environ.get("LLM_API_BASE_URL", "https://api.openai.com/v1"),
        model=os.environ.get("LLM_API_MODEL", "gpt-4o-mini"),
    )


_GRYPE_VULNS_FOUND_RC = 1  # grype convention — not an error

# SBOM tools may invoke lockfile install scripts inside untrusted repos —
# scrub credentials before handing control over.
_SBOM_TOOL_DROP_ENV = ("GIT_TOKEN",)

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

_SBOM_INPUT_SUBDIR = "_sbom_input"


@dataclasses.dataclass(frozen=True)
class DependenciesScanConfig(BaseScanConfig):
    repos: list[str]
    git_token: str | None
    scan_mode: str

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "DependenciesScanConfig":
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
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
            scan_mode=scan_mode,
        )


class DependenciesScanner:
    SCANNER_TYPE = "dependencies"

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ExecutionResult:
        env_vars: dict[str, str] = job.get("envVars") or {}

        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        log_tail: list[str] = []

        try:
            cfg = DependenciesScanConfig.from_job(job)
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

        # Promote ARGUS_* into the process env so download_argus_db can pick
        # them up without re-threading job state.
        for var in ("ARGUS_API_KEY", "ARGUS_ENDPOINT"):
            if var in env_vars and var not in os.environ:
                os.environ[var] = env_vars[var]

        if cfg.scan_mode == SCAN_MODE_ADVISORIES_ONLY:
            return self._run_advisories_only(
                out_dir=out_dir,
                org_label=cfg.org_label,
                run_id=cfg.run_id,
                concurrency=cfg.concurrency,
                backend_client=job["_backend"],
                job_id=job["jobId"],
                on_progress=on_progress,
                cancel_event=cancel_event,
                log_tail=log_tail,
            )

        if cfg.scan_mode == SCAN_MODE_SBOM_ONLY:
            return self._run_sbom_only(
                repos=cfg.repos,
                out_dir=out_dir,
                git_token=cfg.git_token,
                concurrency=cfg.concurrency,
                on_progress=on_progress,
                cancel_event=cancel_event,
                log_tail=log_tail,
            )

        repos = cfg.repos
        emitter = ProgressEmitter(on_progress, expected=len(repos))

        if cancel_event is not None and cancel_event.is_set():
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=CANCELLED_EXIT_CODE, job_dir=out_dir, log_tail=log_tail
            )

        if not repos:
            log_tail.append("[!] No GIT_REPOS specified - nothing to scan")
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

        emitter.starting()

        self._ensure_grype_db(cancel_event)
        custom_db_path = self._resolve_grype_db(out_dir, cancel_event)

        def _scan_one(repo_url: str) -> Path | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            repo_name = repo_name_from_url(repo_url)
            emitter.scanning(repo_name)
            try:
                return self._scan_repo(
                    repo_url,
                    out_dir,
                    git_token=cfg.git_token,
                    custom_db_path=custom_db_path,
                    cancel_event=cancel_event,
                )
            except InsecureURLError as e:
                log_tail.append(f"[!] {e}")
                return None
            except GitCloneError as e:
                log_tail.append(f"[!] {e}")
                return None
            except ScannerTimeoutError as e:
                log_tail.append(f"[!] Timeout scanning {repo_url}: {e}")
                return None
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] Repo {repo_url} failed: {e}")
                logger.exception("[!] Repo %s failed", repo_url)
                return None
            finally:
                emitter.finished(repo_name)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=cfg.concurrency
        ) as pool:
            list(pool.map(_scan_one, repos))

        emitter.normalizing()

        # Aggregate per-repo findings.json into findings.jsonl via the normalize
        # helper (which already walks the target dir).
        try:
            total, errors = normalize.normalize_grype_output(
                cfg.org_label, out_dir, cfg.run_id
            )
            log_tail.append(
                f"[+] Normalized {total} SCA findings ({errors} errors)"
            )
        except Exception as e:  # noqa: BLE001
            log_tail.append(f"[!] Normalization failed: {e}")
            logger.exception("[!] Normalization failed")

        try:
            self._verify_findings_file(out_dir / "findings.jsonl", out_dir)
        except Exception:  # noqa: BLE001
            logger.exception("[!] _verify_findings_file failed (continuing)")
            log_tail.append("[!] verification step failed; findings unverified")

        self._cleanup_checkouts(out_dir)

        write_done_marker(out_dir)
        emitter.done()

        exit_code = 0
        if cancel_event is not None and cancel_event.is_set():
            exit_code = CANCELLED_EXIT_CODE
        return ExecutionResult(
            exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:]
        )

    def _run_advisories_only(
        self,
        *,
        out_dir: Path,
        org_label: str,
        run_id: str,
        concurrency: int,
        backend_client: Any,
        job_id: str,
        on_progress: Callable[[list[str], dict], None] | None,
        cancel_event: threading.Event | None,
        log_tail: list[str],
    ) -> ExecutionResult:
        """Re-run grype against previously stored SBOMs from MinIO.

        Mirrors the ``advisories_only`` branch in run.sh: no clone, no syft,
        no cdxgen. Pulls every ``<org>/<repo>/sbom.json`` from the configured
        S3 bucket, then matches each one against the resolved grype DB.

        Failure to pull SBOMs (missing creds, bucket unreachable, no
        matching keys) is treated as a hard failure with exit_code=2 — an
        empty findings file would silently overwrite the previous run's
        results in the backend.
        """
        emitter = ProgressEmitter(on_progress, expected=0)

        if cancel_event is not None and cancel_event.is_set():
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=CANCELLED_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail,
            )

        emitter.starting()

        sbom_dir = out_dir / _SBOM_INPUT_SUBDIR
        try:
            sbom_count = download_sboms.download_sboms(
                backend_client=backend_client,
                job_id=job_id,
                output_dir=sbom_dir,
            )
        except Exception as e:  # noqa: BLE001
            message = f"[!] advisories_only: SBOM download error: {e}"
            log_tail.append(message)
            logger.exception("[!] advisories_only: SBOM download error")
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=_UNSUPPORTED_MODE_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail[-50:],
            )

        sbom_files = sorted(sbom_dir.glob("*.json")) if sbom_dir.exists() else []
        if not sbom_files:
            message = (
                f"[!] advisories_only: no SBOMs available for org "
                f"{org_label!r} (downloaded {sbom_count})"
            )
            log_tail.append(message)
            logger.warning(message)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=_UNSUPPORTED_MODE_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail[-50:],
            )

        log_tail.append(
            f"[+] advisories_only mode: matching {len(sbom_files)} SBOMs"
        )

        # Re-key emitter to the real expected count now that we know it.
        emitter = ProgressEmitter(on_progress, expected=len(sbom_files))
        emitter.starting()

        self._ensure_grype_db(cancel_event)
        custom_db_path = self._resolve_grype_db(out_dir, cancel_event)

        def _match_one(sbom_file: Path) -> Path | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            repo_key = sbom_file.stem
            # download_sboms encodes "/" as "__"; reverse for the per-repo
            # output directory so the normalizer recovers a canonical name.
            repo_name = repo_key.replace("__", "/")
            emitter.scanning(repo_name)
            try:
                return self._match_sbom(
                    sbom_file=sbom_file,
                    repo_name=repo_name,
                    out_dir=out_dir,
                    custom_db_path=custom_db_path,
                    cancel_event=cancel_event,
                )
            except ScannerTimeoutError as e:
                log_tail.append(f"[!] Timeout matching {repo_name}: {e}")
                return None
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] Match {repo_name} failed: {e}")
                logger.exception("[!] Match %s failed", repo_name)
                return None
            finally:
                emitter.finished(repo_name)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=concurrency
        ) as pool:
            list(pool.map(_match_one, sbom_files))

        emitter.normalizing()

        try:
            total, errors = normalize.normalize_grype_output(
                org_label, out_dir, run_id
            )
            log_tail.append(
                f"[+] Normalized {total} SCA findings ({errors} errors)"
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

    def _run_sbom_only(
        self,
        *,
        repos: list[str],
        out_dir: Path,
        git_token: str | None,
        concurrency: int,
        on_progress: Callable[[list[str], dict], None] | None,
        cancel_event: threading.Event | None,
        log_tail: list[str],
    ) -> ExecutionResult:
        """sbom_only: per-repo clone + SBOM build + register, no grype.

        Reuses ``_scan_repo`` with ``skip_grype=True`` so the clone + syft +
        cdxgen + tag + register flow is shared with the full path. No
        ``findings.jsonl`` is written — bash produces no per-repo
        ``findings.json`` in this mode so the aggregate file is absent too.
        """
        emitter = ProgressEmitter(on_progress, expected=len(repos))

        if cancel_event is not None and cancel_event.is_set():
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=CANCELLED_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail,
            )

        if not repos:
            log_tail.append("[!] No GIT_REPOS specified - nothing to scan")
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=0, job_dir=out_dir, log_tail=log_tail
            )

        emitter.starting()

        def _scan_one(repo_url: str) -> None:
            if cancel_event is not None and cancel_event.is_set():
                return
            repo_name = repo_name_from_url(repo_url)
            emitter.scanning(repo_name)
            try:
                self._scan_repo(
                    repo_url,
                    out_dir,
                    git_token=git_token,
                    custom_db_path=None,
                    cancel_event=cancel_event,
                    skip_grype=True,
                )
            except InsecureURLError as e:
                log_tail.append(f"[!] {e}")
            except GitCloneError as e:
                log_tail.append(f"[!] {e}")
            except ScannerTimeoutError as e:
                log_tail.append(f"[!] Timeout scanning {repo_url}: {e}")
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] Repo {repo_url} failed: {e}")
                logger.exception("[!] Repo %s failed", repo_url)
            finally:
                emitter.finished(repo_name)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=concurrency
        ) as pool:
            list(pool.map(_scan_one, repos))

        emitter.normalizing()
        write_done_marker(out_dir)
        emitter.done()

        exit_code = (
            CANCELLED_EXIT_CODE
            if (cancel_event is not None and cancel_event.is_set())
            else 0
        )
        return ExecutionResult(
            exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:]
        )

    def _match_sbom(
        self,
        *,
        sbom_file: Path,
        repo_name: str,
        out_dir: Path,
        custom_db_path: Path | None,
        cancel_event: threading.Event | None,
    ) -> Path | None:
        """Copy a downloaded SBOM into its per-repo output dir and run grype.

        Mirrors the per-SBOM block in the bash ``advisories_only`` flow:
        copy SBOM -> register output -> grype match -> register findings.
        """
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        log_scanning(repo_name)

        merged_sbom = repo_out / "sbom.cdx.json"
        try:
            shutil.copyfile(sbom_file, merged_sbom)
        except OSError as e:
            logger.warning("[!] Failed to copy SBOM for %s: %s", repo_name, e)
            log_finished(repo_name)
            return None

        register_output(out_dir, merged_sbom, repo_name)

        findings_json = repo_out / "findings.json"
        self._run_grype(
            merged_sbom, findings_json, custom_db_path, cancel_event
        )

        log_finished(repo_name)
        return findings_json if findings_json.exists() else None

    # ------------------------------------------------------------------
    # verification
    # ------------------------------------------------------------------

    def _verify_findings_file(
        self, findings_file: Path, out_dir: Path
    ) -> None:
        """Read findings.jsonl, run prefilter + verify, rewrite in place."""
        if not findings_file.exists():
            return

        raw_findings: list[dict] = []
        for line in findings_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                raw_findings.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("[!] skip non-JSON line in %s", findings_file)

        verified = self._maybe_verify_sca(
            findings=raw_findings,
            out_dir=out_dir,
            llm=_build_llm_client(),
            scan_budget=make_sca_budget(),
        )

        with open(findings_file, "w") as f:
            for finding in verified:
                f.write(json.dumps(finding, separators=(",", ":")) + "\n")

    def _maybe_verify_sca(
        self,
        *,
        findings: list[dict],
        out_dir: Path,
        llm,
        scan_budget: ScanBudget,
    ) -> list[dict]:
        out: list[dict] = []
        for f in findings:
            copy = dict(f)
            metadata: dict = copy.setdefault("verification_metadata", {})

            if llm is None:
                copy["verdict"] = None
                metadata["skipped"] = "llm_disabled"
                out.append(copy)
                continue

            repo_name = copy.get("repository", "")
            clone_dir = out_dir / repo_name / "_checkout" if repo_name else None
            import_sites_dicts: list[dict] = []
            if (
                clone_dir is not None
                and clone_dir.exists()
                and copy.get("packageName")
                and copy.get("ecosystem")
            ):
                sites = find_import_sites(
                    clone_dir,
                    copy["packageName"],
                    copy["ecosystem"],
                )
                import_sites_dicts = [s.to_dict() for s in sites]

            decision = prefilter_sca_finding(
                copy, import_sites=import_sites_dicts
            )
            if decision.skip_llm:
                copy["verdict"] = decision.verdict
                metadata["prefilter"] = decision.to_dict()
                out.append(copy)
                continue

            if not scan_budget.allow():
                copy["verdict"] = "possible"
                metadata["skipped"] = scan_budget.skip_reason
                out.append(copy)
                continue

            sev = (copy.get("severity") or "").lower()
            if sev not in _MIN_VERIFY_SEVERITY:
                copy["verdict"] = None
                metadata["skipped"] = "below_severity"
                out.append(copy)
                continue

            try:
                repo_root = (
                    str(clone_dir) if clone_dir is not None and clone_dir.exists()
                    else str(out_dir)
                )
                result = verify_sca_finding(
                    finding=copy,
                    repo_root=repo_root,
                    llm=llm,
                    import_sites=import_sites_dicts,
                )
                scan_budget.record(
                    tokens_in=result.tokens_in, tokens_out=result.tokens_out
                )
                copy["verdict"] = result.verdict
                copy["evidence_json"] = result.evidence
                copy["exploit_chain"] = result.exploit_chain
                copy["verification_metadata"] = result.verification_metadata
            except Exception as e:  # noqa: BLE001
                copy["verdict"] = None
                metadata["skipped"] = f"llm_error:{type(e).__name__}"
                logger.exception("[!] sca verification failed for %s", copy.get("advisoryId"))

            out.append(copy)
        return out

    def _cleanup_checkouts(self, out_dir: Path) -> None:
        """Remove every per-repo ``_checkout`` directory. Best-effort."""
        for pattern in ("*/_checkout", "*/*/_checkout"):
            for checkout in out_dir.glob(pattern):
                try:
                    shutil.rmtree(checkout, ignore_errors=True)
                except OSError as exc:
                    logger.debug("checkout cleanup failed for %s: %s", checkout, exc)

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _resolve_grype_db(
        self,
        out_dir: Path,
        cancel_event: threading.Event | None,
    ) -> Path | None:
        """Resolve which advisory DB grype should use.

        Precedence (mirrors bash run.sh):
            1. Argus paid-tier DB — when ARGUS_API_KEY + ARGUS_ENDPOINT set
               and the download succeeds.
            2. vunnel-built custom DB — when ADVISORY_PROVIDERS set and the
               build succeeds.
            3. None → grype falls back to its built-in DB.
        """
        argus_work_dir = out_dir / "_argus"
        argus_path = argus_db.download_argus_db(
            argus_work_dir, cancel_event=cancel_event
        )
        if argus_path is not None:
            logger.info("[+] Using Argus advisory DB")
            return argus_path

        vunnel_path = advisory_db.build_custom_advisory_db(
            cancel_event=cancel_event
        )
        if vunnel_path is not None:
            logger.info("[+] Using vunnel custom DB")
            return vunnel_path

        return None

    def _ensure_grype_db(self, cancel_event: threading.Event | None) -> None:
        if shutil.which("grype") is None:
            logger.warning("[!] grype not on PATH - skipping DB check")
            return
        rc, _, _ = run_tool(
            ["grype", "db", "check"],
            timeout=TIMEOUT_GRYPE_DB_CHECK,
            cancel_event=cancel_event,
        )
        if rc == 0:
            return
        logger.info("[+] Updating Grype vulnerability database...")
        rc, _, stderr = run_tool(
            ["grype", "db", "update"],
            timeout=TIMEOUT_GRYPE_DB_UPDATE,
            cancel_event=cancel_event,
        )
        if rc != 0:
            logger.warning(
                "[!] Grype DB update failed - scanning may produce incomplete "
                "results: %s",
                (stderr or "")[:200],
            )

    def _scan_repo(
        self,
        repo_url: str,
        out_dir: Path,
        *,
        git_token: str | None,
        custom_db_path: Path | None,
        cancel_event: threading.Event | None,
        skip_grype: bool = False,
    ) -> Path | None:
        repo_name = repo_name_from_url(repo_url)
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        log_scanning(repo_name)

        clone_dir = repo_out / "_checkout"
        try:
            clone_repo(
                repo_url, clone_dir, token=git_token, timeout=TIMEOUT_CLONE
            )
        finally:
            pass

        head_sha = self._read_head_sha(clone_dir, cancel_event)
        (repo_out / "head-sha.txt").write_text(head_sha + "\n")

        syft_sbom = repo_out / "syft-sbom.cdx.json"
        cdxgen_sbom = repo_out / "cdxgen-sbom.cdx.json"
        merged_sbom = repo_out / "sbom.cdx.json"

        syft_ok = self._run_syft(clone_dir, syft_sbom, cancel_event)
        cdxgen_ok = self._run_cdxgen(clone_dir, cdxgen_sbom, cancel_event)

        if syft_ok and cdxgen_ok:
            if not self._merge_sboms(syft_sbom, cdxgen_sbom, merged_sbom):
                shutil.copy(syft_sbom, merged_sbom)
        elif syft_ok:
            shutil.copy(syft_sbom, merged_sbom)
        elif cdxgen_ok:
            shutil.copy(cdxgen_sbom, merged_sbom)
        else:
            logger.warning(
                "[!] Both SBOM generators failed for %s - skipping", repo_name
            )
            log_finished(repo_name)
            shutil.rmtree(clone_dir, ignore_errors=True)
            return None

        register_output(out_dir, merged_sbom, repo_name)

        # sbom_only path: SBOM built + registered, skip grype + manifest
        # extraction (no findings.json to enrich with snippets).
        if skip_grype:
            log_finished(repo_name)
            shutil.rmtree(clone_dir, ignore_errors=True)
            return None

        manifests_dir = repo_out / "manifests"
        manifests_dir.mkdir(exist_ok=True)
        self._extract_manifests(
            merged_sbom, syft_sbom, clone_dir, manifests_dir
        )

        findings_json = repo_out / "findings.json"
        self._run_grype(
            merged_sbom, findings_json, custom_db_path, cancel_event
        )

        log_finished(repo_name)
        # Clone preserved until _cleanup_checkouts; verifier needs it for import sites.
        return findings_json if findings_json.exists() else None

    def _read_head_sha(
        self, clone_dir: Path, cancel_event: threading.Event | None
    ) -> str:
        rc, stdout, _ = run_tool(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            timeout=30.0,
            cancel_event=cancel_event,
        )
        if rc != 0:
            return "unknown"
        return stdout.strip() or "unknown"

    def _run_syft(
        self,
        target: Path,
        output: Path,
        cancel_event: threading.Event | None,
    ) -> bool:
        if shutil.which("syft") is None:
            return False
        rc, stdout, stderr = run_tool(
            [
                "syft",
                str(target),
                "-o",
                "cyclonedx-json",
                "--parallelism",
                "2",
            ],
            timeout=TIMEOUT_SYFT_REPO,
            drop_env=_SBOM_TOOL_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc != 0:
            logger.warning("[!] Syft failed: %s", (stderr or "")[:200])
            return False
        output.write_text(stdout)
        self._tag_sbom_source(output, "syft")
        return True

    def _run_cdxgen(
        self,
        target: Path,
        output: Path,
        cancel_event: threading.Event | None,
    ) -> bool:
        if shutil.which("cdxgen") is None:
            return False
        rc, _, stderr = run_tool(
            ["cdxgen", "-o", str(output), str(target), "--no-recurse"],
            timeout=TIMEOUT_CDXGEN,
            drop_env=_SBOM_TOOL_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc != 0 or not output.exists() or output.stat().st_size == 0:
            logger.warning("[!] cdxgen failed: %s", (stderr or "")[:200])
            return False
        self._tag_sbom_source(output, "cdxgen")
        return True

    def _merge_sboms(
        self, syft_sbom: Path, cdxgen_sbom: Path, merged: Path
    ) -> bool:
        if shutil.which("cyclonedx") is None:
            return False
        rc, _, _ = run_tool(
            [
                "cyclonedx",
                "merge",
                "--input-files",
                str(syft_sbom),
                str(cdxgen_sbom),
                "--output-file",
                str(merged),
                "--output-format",
                "json",
            ],
            timeout=120.0,
            env={"DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "true"},
            drop_env=_SBOM_TOOL_DROP_ENV,
        )
        return rc == 0 and merged.exists() and merged.stat().st_size > 0

    def _tag_sbom_source(self, sbom_file: Path, tool_name: str) -> None:
        """Append a {"name": "scanner:source", "value": <tool>} property to every
        component — mirrors the jq one-liner in the bash original."""
        if not sbom_file.exists() or sbom_file.stat().st_size == 0:
            return
        try:
            data = json.loads(sbom_file.read_text())
        except (json.JSONDecodeError, OSError):
            return
        components = data.get("components") or []
        for comp in components:
            props = comp.get("properties") or []
            props.append({"name": "scanner:source", "value": tool_name})
            comp["properties"] = props
        try:
            sbom_file.write_text(json.dumps(data, separators=(",", ":")))
        except OSError:
            pass

    def _extract_manifests(
        self,
        merged_sbom: Path,
        syft_sbom: Path,
        clone_dir: Path,
        manifests_dir: Path,
    ) -> int:
        """Copy manifest files referenced by the SBOM into ``manifests_dir``.

        Mirrors the bash ``scan_repository`` block (run.sh:215-247) so the
        normalizer can locate manifests for snippet enrichment. Files are
        saved as ``<clean_path with slashes replaced by __>`` to match the
        flattened lookup performed in :mod:`runner.scanners.dependencies.normalize`.
        """
        if not merged_sbom.exists() or merged_sbom.stat().st_size == 0:
            return 0
        try:
            clone_root = clone_dir.resolve()
        except OSError:
            return 0

        paths = self._sbom_manifest_paths(
            merged_sbom, ("cdx:npm:package:path", "syft:location:0:path")
        )
        if not paths and syft_sbom.exists() and syft_sbom.stat().st_size > 0:
            paths = self._sbom_manifest_paths(syft_sbom, prefix="syft:location")

        copied = 0
        for raw_path in paths:
            if not raw_path:
                continue
            clean = raw_path.lstrip("/")
            if not clean or ".." in clean.split("/"):
                continue
            try:
                resolved = (clone_root / clean).resolve()
            except OSError:
                continue
            try:
                resolved.relative_to(clone_root)
            except ValueError:
                continue
            if not resolved.is_file():
                continue
            safe_name = clean.replace("/", "__")
            dest = manifests_dir / safe_name
            try:
                shutil.copyfile(resolved, dest)
                copied += 1
            except OSError:
                continue
        return copied

    @staticmethod
    def _sbom_manifest_paths(
        sbom_file: Path,
        names: tuple[str, ...] = (),
        *,
        prefix: str | None = None,
    ) -> list[str]:
        """Return the sorted-unique set of manifest paths declared in an SBOM.

        Matches the jq filters in run.sh: select properties whose ``name``
        is in ``names`` OR (when ``prefix`` is given) starts with that prefix.
        """
        try:
            data = json.loads(sbom_file.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        found: set[str] = set()
        for comp in data.get("components") or []:
            for prop in comp.get("properties") or []:
                name = prop.get("name") or ""
                if name in names or (prefix is not None and name.startswith(prefix)):
                    value = prop.get("value")
                    if isinstance(value, str) and value:
                        found.add(value)
        return sorted(found)

    def _run_grype(
        self,
        sbom: Path,
        output: Path,
        custom_db_path: Path | None,
        cancel_event: threading.Event | None,
    ) -> bool:
        if shutil.which("grype") is None:
            return False
        args = ["grype", f"sbom:{sbom}", "-o", "json", "--quiet"]
        if custom_db_path and custom_db_path.exists():
            args.extend(["--db", str(custom_db_path)])
        rc, stdout, stderr = run_tool(
            args, timeout=TIMEOUT_GRYPE_MATCH, cancel_event=cancel_event
        )
        # Exit 1 = vulnerabilities found (not an error)
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

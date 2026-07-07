"""DepsReachabilityScanner — per-finding dependency reachability job handler.

Consumes a ``dependencies_reachability`` job: clone the target repo once, run the
grounded reachability verifier (:func:`verify_deps_finding`) over each requested
target finding, and write a single ``reachability-results.json`` for the backend
to ingest. The runner emits only the tri-state reachability signal (plus an
optional deterministic upgrade suggestion); the backend owns the reachability x
KEV x EPSS fuse and any hide decision.
"""
from __future__ import annotations

import dataclasses
import json
import logging
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
    TIMEOUT_CLONE,
    build_escalation_llm_client,
    build_llm_client,
    clone_repo,
    log,
    parse_repos,
    register_output,
    repo_name_from_url,
)
from runner.scanners._subprocess import CANCELLED_EXIT_CODE
from runner.scanners.base import ExecutionResult
from runner.verification.verifiers.deps import verify_deps_finding

logger = logging.getLogger(__name__)

# Config problems (missing repo / malformed targets) are caller errors, not
# transient failures — surface a distinct non-zero code from a cancelled run.
_CONFIG_ERROR_EXIT_CODE = 2

_RESULTS_FILENAME = "reachability-results.json"


@dataclasses.dataclass(frozen=True)
class DepsReachabilityConfig(BaseScanConfig):
    repos: list[str]
    git_token: str | None
    targets: list[dict]

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "DepsReachabilityConfig":
        env = JobEnv(job)
        repos = parse_repos(env.get("GIT_REPOS"))
        if not repos:
            raise ScannerConfigError("[!] No GIT_REPOS specified for reachability job")

        targets = _parse_targets(env.get("REACHABILITY_TARGETS"))

        return cls(
            org_label=env.get("ORG_LABEL", "default"),
            run_id=env.get("RUN_ID", str(job.get("jobId", "unknown"))),
            concurrency=1,
            repos=repos,
            git_token=env.get("GIT_TOKEN") or None,
            targets=targets,
        )


def _parse_targets(raw: str) -> list[dict]:
    """Parse REACHABILITY_TARGETS into a list of target dicts.

    Fails loudly on absent/malformed input — a reachability job with no valid
    target list is a caller error, not something to silently treat as empty.
    """
    if not raw:
        raise ScannerConfigError("[!] REACHABILITY_TARGETS is missing")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ScannerConfigError(
            f"[!] REACHABILITY_TARGETS is not valid JSON: {exc}"
        ) from None
    if not isinstance(parsed, list):
        raise ScannerConfigError("[!] REACHABILITY_TARGETS must be a JSON array")
    return [t for t in parsed if isinstance(t, dict)]


class DepsReachabilityScanner:
    SCANNER_TYPE = "dependencies_reachability"

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ExecutionResult:
        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        log_tail: list[str] = []

        try:
            cfg = DepsReachabilityConfig.from_job(job)
        except ScannerConfigError as exc:
            message = str(exc)
            logger.error(message)
            log_tail.append(message)
            emitter = ProgressEmitter(on_progress, expected=0)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=_CONFIG_ERROR_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail,
            )

        emitter = ProgressEmitter(on_progress, expected=1)

        if cancel_event is not None and cancel_event.is_set():
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=CANCELLED_EXIT_CODE, job_dir=out_dir, log_tail=log_tail
            )

        # Backend gates enqueue on verification being enabled, so a live job
        # should always carry a key. Degrade to an empty result rather than
        # crash if it somehow doesn't.
        env = JobEnv(job)
        llm = build_llm_client(env)
        if llm is None:
            log_tail.append("[*] LLM_API_KEY not set — writing empty reachability results")
            self._write_results(out_dir, cfg.run_id, [], repo="reachability", log_tail=log_tail)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)
        escalation_llm = build_escalation_llm_client(env)

        repo_url = cfg.repos[0]
        repo_name = repo_name_from_url(repo_url)
        emitter.starting()
        emitter.scanning(repo_name)

        clone_dir = out_dir / repo_name / "_checkout"
        try:
            log("scanning", repo_name)
            clone_repo(
                repo_url,
                clone_dir,
                token=cfg.git_token,
                depth=1,
                timeout=TIMEOUT_CLONE,
            )
        except (InsecureURLError, GitCloneError) as exc:
            # A clone we can't complete leaves nothing to judge; fail the job
            # rather than emitting a misleading all-unknown result set.
            log_tail.append(f"[!] {exc}")
            emitter.finished(repo_name)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=1, job_dir=out_dir, log_tail=log_tail)

        try:
            results = self._verify_targets(
                cfg.targets, clone_dir, llm, escalation_llm, cancel_event, log_tail
            )
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
            emitter.finished(repo_name)

        self._write_results(out_dir, cfg.run_id, results, repo=repo_name, log_tail=log_tail)
        log_tail.append(f"[✓] reachability judged {len(results)} finding(s)")

        emitter.done()
        write_done_marker(out_dir)

        exit_code = 0
        if cancel_event is not None and cancel_event.is_set():
            exit_code = CANCELLED_EXIT_CODE
        return ExecutionResult(
            exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:]
        )

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _verify_targets(
        self,
        targets: list[dict],
        clone_dir: Path,
        llm,
        escalation_llm,
        cancel_event: threading.Event | None,
        log_tail: list[str],
    ) -> list[dict]:
        results: list[dict] = []
        for target in targets:
            if cancel_event is not None and cancel_event.is_set():
                break

            finding = {
                "packageName": target.get("package"),
                "packageVersion": target.get("version"),
                "ecosystem": target.get("ecosystem"),
                "cve": target.get("cve"),
            }
            try:
                result = verify_deps_finding(
                    finding=finding, repo_root=str(clone_dir), llm=llm,
                    escalation_llm=escalation_llm,
                )
                metadata = result.verification_metadata or {}
                results.append({
                    "finding_id": target.get("finding_id"),
                    "reachability": metadata.get("reachability"),
                    "evidence": result.evidence,
                    "recommended_fix": metadata.get("recommended_fix"),
                })
            except Exception as exc:  # noqa: BLE001 — one bad target must not sink the job
                logger.exception("[!] reachability verify failed for a target")
                log_tail.append(f"[!] target verify failed: {type(exc).__name__}")
                results.append({
                    "finding_id": target.get("finding_id"),
                    "reachability": "unknown",
                    "evidence": [],
                    "recommended_fix": None,
                })
        return results

    def _write_results(
        self,
        out_dir: Path,
        run_id: str,
        results: list[dict],
        *,
        repo: str,
        log_tail: list[str],
    ) -> None:
        """Write reachability-results.json and register it for upload."""
        # Namespace by repo so per-asset jobs that share a run_id don't collide on
        # one object-store key (which would silently overwrite all but one asset's
        # results). Mirrors the SBOM layout ({repo}/sbom.cdx.json).
        results_dir = out_dir / repo
        results_dir.mkdir(parents=True, exist_ok=True)
        results_path = results_dir / _RESULTS_FILENAME
        payload = {"run_id": run_id, "results": results}
        try:
            results_path.write_text(json.dumps(payload, separators=(",", ":")))
        except OSError as exc:
            log_tail.append(f"[!] failed to write {_RESULTS_FILENAME}: {exc}")
            return
        register_output(out_dir, results_path, repo)
        log("done", repo)

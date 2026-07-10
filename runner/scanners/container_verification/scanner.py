"""ContainerVerificationScanner — per-finding container CVE enrichment job handler.

Consumes ``container_verification`` jobs: reads target findings from env var
``CONTAINER_VERIFY_TARGETS`` (a JSON list), calls the container enrichment
verifier over each, and writes ``container-verify-results.json`` for backend
ingest. No repo clone is performed — container verification works from advisory
and image metadata alone.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import threading
from pathlib import Path
from typing import Any, Callable

from runner.scanners._manifest import write_done_marker
from runner.scanners._shared import (
    BaseScanConfig,
    JobEnv,
    ProgressEmitter,
    ScannerConfigError,
    build_llm_client,
    log,
    register_output,
)
from runner.scanners._subprocess import CANCELLED_EXIT_CODE
from runner.scanners.base import ExecutionResult
from runner.verification.verifiers.container import verify_container_finding

logger = logging.getLogger(__name__)

_CONFIG_ERROR_EXIT_CODE = 2
_RESULTS_FILENAME = "container-verify-results.json"


@dataclasses.dataclass(frozen=True)
class ContainerVerificationConfig(BaseScanConfig):
    targets: list[dict]

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "ContainerVerificationConfig":
        env = JobEnv(job)
        targets = _parse_targets(env.get("CONTAINER_VERIFY_TARGETS"))
        return cls(
            org_label=env.get("ORG_LABEL", "default"),
            run_id=env.get("RUN_ID", str(job.get("jobId", "unknown"))),
            concurrency=1,
            targets=targets,
        )


def _parse_targets(raw: str) -> list[dict]:
    """Parse CONTAINER_VERIFY_TARGETS into a list of target dicts.

    Fails loudly on absent/malformed input — a container verification job with
    no valid target list is a caller error, not something to silently treat as empty.
    """
    if not raw:
        raise ScannerConfigError("[!] CONTAINER_VERIFY_TARGETS is missing")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ScannerConfigError(
            f"[!] CONTAINER_VERIFY_TARGETS is not valid JSON: {exc}"
        ) from None
    if not isinstance(parsed, list):
        raise ScannerConfigError("[!] CONTAINER_VERIFY_TARGETS must be a JSON array")
    return [t for t in parsed if isinstance(t, dict)]


class ContainerVerificationScanner:
    SCANNER_TYPE = "container_verification"

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
            cfg = ContainerVerificationConfig.from_job(job)
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

        env = JobEnv(job)
        llm = build_llm_client(env)
        if llm is None:
            log_tail.append("[*] LLM_API_KEY not configured — skipping verification")
            self._write_results(out_dir, cfg.run_id, [], log_tail=log_tail)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

        emitter.starting()

        results = self._verify_targets(cfg.targets, llm, cancel_event, log_tail)
        log_tail.append(f"[✓] container enrichment verified {len(results)} finding(s)")

        self._write_results(out_dir, cfg.run_id, results, log_tail=log_tail)

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
        llm,
        cancel_event: threading.Event | None,
        log_tail: list[str],
    ) -> list[dict]:
        results: list[dict] = []
        for target in targets:
            if cancel_event is not None and cancel_event.is_set():
                break
            try:
                result = verify_container_finding(finding=target, llm=llm)
                results.append({
                    "finding_id": target.get("finding_id"),
                    "verdict": result.verdict,
                    "evidence": result.evidence,
                    "verification_metadata": result.verification_metadata,
                })
            except Exception as exc:  # noqa: BLE001 — one bad target must not sink the job
                logger.exception("[!] container verify failed for a target")
                log_tail.append(f"[!] target verify failed: {type(exc).__name__}")
                results.append({"finding_id": target.get("finding_id")})
        return results

    def _write_results(
        self,
        out_dir: Path,
        run_id: str,
        results: list[dict],
        *,
        log_tail: list[str],
    ) -> None:
        """Write container-verify-results.json and register it for upload."""
        results_path = out_dir / _RESULTS_FILENAME
        payload = {"run_id": run_id, "results": results}
        try:
            results_path.write_text(json.dumps(payload, separators=(",", ":")))
        except OSError as exc:
            log_tail.append(f"[!] failed to write {_RESULTS_FILENAME}: {exc}")
            return
        register_output(out_dir, results_path, "container_verification")
        log("done", "container_verification")

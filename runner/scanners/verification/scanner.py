"""Runs the aggregate orchestrator / correlator / dedupe pipeline as a scanner job.

Inputs are read from ``job_dir/input/<scanner>/findings.jsonl``; optional repo
clones live at ``job_dir/input/<repo>/_checkout/``. Output is
``aggregate-verification.json`` in ``job_dir``.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Callable

from runner.scanners._manifest import write_done_marker
from runner.scanners._shared import JobEnv, ProgressEmitter
from runner.scanners.base import ExecutionResult
from runner.verification.pipelines.aggregate import run_aggregate_verification

logger = logging.getLogger(__name__)


_INPUT_SUBDIR = "input"
_OUTPUT_FILENAME = "aggregate-verification.json"


class VerificationScanner:
    SCANNER_TYPE = "verification"

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

        emitter = ProgressEmitter(on_progress, expected=1)

        if cancel_event is not None and cancel_event.is_set():
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

        env = JobEnv(job)
        total_budget = env.get_int(
            "AGGREGATE_VERIFICATION_BUDGET", 200_000
        )

        input_dir = out_dir / _INPUT_SUBDIR
        findings = _collect_input_findings(input_dir, log_tail)
        log_tail.append(f"[+] aggregate verification: {len(findings)} input findings")

        if not findings:
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

        repo_root_for = _build_repo_root_map(input_dir, findings)
        if repo_root_for:
            log_tail.append(
                f"[+] mapped {len(repo_root_for)} repo clones for correlator tools"
            )

        emitter.starting()

        # Correlation runs on the LLM Service; the deterministic orchestrator +
        # dedupe stay local either way. Argus is threat-intel enrichment data,
        # not a correlation service, so it never routes the correlation step.
        llm = _build_llm_client(env)
        correlate_fn = None
        if llm is None:
            log_tail.append(
                "[*] LLM_API_KEY not set — running orchestrator + dedupe only "
                "(correlation step skipped)"
            )

        try:
            result = run_aggregate_verification(
                findings,
                repo_root_for=repo_root_for,
                llm=llm,
                correlate_fn=correlate_fn,
                total_budget=total_budget,
            )
        except Exception as exc:  # noqa: BLE001
            log_tail.append(f"[!] aggregate verification failed: {exc}")
            logger.exception("aggregate verification failed")
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=1, job_dir=out_dir, log_tail=log_tail)

        output_path = out_dir / _OUTPUT_FILENAME
        try:
            output_path.write_text(
                json.dumps(result.to_dict(), separators=(",", ":"))
            )
        except OSError as exc:
            log_tail.append(f"[!] failed to write {_OUTPUT_FILENAME}: {exc}")

        log_tail.append(
            f"[✓] correlated={result.summary['correlated_chains']} "
            f"deduped={result.summary['merged_findings']} "
            f"primaries={result.summary['final_primaries']}"
        )

        emitter.done()
        write_done_marker(out_dir)
        return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail[-50:])


def _collect_input_findings(input_dir: Path, log_tail: list[str]) -> list[dict]:
    """Read every findings.jsonl under input_dir (one per scanner)."""
    if not input_dir.exists() or not input_dir.is_dir():
        return []
    findings: list[dict] = []
    for path in sorted(input_dir.rglob("findings.jsonl")):
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError as exc:
            log_tail.append(f"[!] could not read {path}: {exc}")
    return findings


def _build_repo_root_map(input_dir: Path, findings: list[dict]) -> dict[str, Path]:
    """Map repository names → per-repo clone paths under ``input_dir``."""
    out: dict[str, Path] = {}
    repos = {(f.get("repository") or "").strip() for f in findings}
    for repo in repos:
        if not repo:
            continue
        candidate = input_dir / repo / "_checkout"
        if candidate.exists() and candidate.is_dir():
            out[repo] = candidate
    return out


def _build_llm_client(env: JobEnv):
    """Return an LLM client or None when LLM_API_KEY is unset.

    Reads from job['envVars'] via JobEnv — the backend ships LLM config there,
    not in the runner process environment.
    """
    from runner.verification.llm_client import LlmClient

    api_key = env.get("LLM_API_KEY")
    if not api_key:
        return None
    return LlmClient(
        api_key=api_key,
        api_base_url=env.get("LLM_API_BASE_URL", "https://api.openai.com/v1"),
        model=env.get("LLM_API_MODEL", "gpt-4o-mini"),
    )

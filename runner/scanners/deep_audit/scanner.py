"""DeepAuditScanner — reasoning-based discovery of broken access control.

Clones each repo and audits its route handlers for missing authorization /
IDOR-BOLA — the class semgrep structurally can't reach. The LLM hunter proposes
candidates; every verdict is then decided by the shared verification pipeline
(skeptic + citation critic + ground-truth carve-outs), not a parallel engine.

Opt-in and LLM-only: with no BYO model configured it is a no-op.
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
    GitCloneError,
    InsecureURLError,
    JobEnv,
    ProgressEmitter,
    TIMEOUT_CLONE,
    build_escalation_llm_client,
    build_llm_client,
    clone_repo,
    derive_html_url,
    parse_repos,
    register_output,
    repo_name_from_url,
)
from runner.scanners._subprocess import CANCELLED_EXIT_CODE
from runner.scanners.base import ExecutionResult
from runner.scanners.deep_audit.engine import audit_repo
from runner.verification.budget import make_deep_audit_budget, verify_concurrency

logger = logging.getLogger(__name__)

_FAILURE_EXIT_CODE = 2
_DEFAULT_MAX_FILES = 40
_DEFAULT_MAX_CHARS = 8000


def _accepted_risks(env: JobEnv) -> list:
    """User-declared carve-outs passed through the job env; fail-open to []."""
    try:
        risks = json.loads(env.get("ACCEPTED_RISKS") or "[]")
    except (TypeError, ValueError):
        return []
    return risks if isinstance(risks, list) else []


@dataclasses.dataclass(frozen=True)
class DeepAuditConfig:
    repos: list[str]
    git_token: str | None

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "DeepAuditConfig":
        env = JobEnv(job)
        return cls(
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
        )


class DeepAuditScanner:
    SCANNER_TYPE = "deep_audit"

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
        backend=None,
    ) -> ExecutionResult:
        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        log_tail: list[str] = []

        cfg = DeepAuditConfig.from_job(job)
        repos = cfg.repos
        emitter = ProgressEmitter(on_progress, expected=len(repos))

        if cancel_event is not None and cancel_event.is_set():
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=CANCELLED_EXIT_CODE, job_dir=out_dir, log_tail=log_tail)

        env = JobEnv(job)
        llm = build_llm_client(env)

        # Reasoning audit needs a model; otherwise no-op (like the other LLM steps).
        if not repos or llm is None:
            reason = "no GIT_REPOS" if not repos else "no LLM configured (deep audit is reasoning-based)"
            log_tail.append(f"[!] deep audit skipped — {reason}")
            self._write(out_dir, [])
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

        emitter.starting()
        escalation_llm = build_escalation_llm_client(env)
        budget = make_deep_audit_budget(env)
        workers = verify_concurrency(env)
        accepted_risks = _accepted_risks(env)
        max_files = env.get_int("DEEP_AUDIT_MAX_FILES", _DEFAULT_MAX_FILES)
        max_chars = env.get_int("DEEP_AUDIT_MAX_FILE_CHARS", _DEFAULT_MAX_CHARS)

        all_findings: list[dict] = []
        any_clone_failed = False
        for repo_url in repos:
            if cancel_event is not None and cancel_event.is_set():
                break
            findings, cloned = self._scan_one_repo(
                repo_url, out_dir, cfg.git_token,
                llm=llm, escalation_llm=escalation_llm, budget=budget, workers=workers,
                accepted_risks=accepted_risks, max_files=max_files, max_chars=max_chars,
                cancel_event=cancel_event, log_tail=log_tail, emitter=emitter,
            )
            any_clone_failed = any_clone_failed or not cloned
            all_findings.extend(findings)

        self._write(out_dir, all_findings)
        log_tail.append(f"[+] deep audit complete — {len(all_findings)} findings across {len(repos)} repo(s)")
        emitter.normalizing()
        write_done_marker(out_dir)
        emitter.done()

        exit_code = 0
        if cancel_event is not None and cancel_event.is_set():
            exit_code = CANCELLED_EXIT_CODE
        elif any_clone_failed and not all_findings:
            exit_code = _FAILURE_EXIT_CODE
        return ExecutionResult(exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:])

    def _write(self, out_dir: Path, findings: list[dict]) -> None:
        findings_path = out_dir / "findings.jsonl"
        with findings_path.open("w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(f) + "\n")
        register_output(out_dir, findings_path, "_all")

    def _scan_one_repo(
        self, repo_url, out_dir, git_token, *, llm, escalation_llm, budget, workers,
        accepted_risks, max_files, max_chars, cancel_event, log_tail, emitter,
    ) -> tuple[list[dict], bool]:
        repo_name = repo_name_from_url(repo_url)
        clone_dir = out_dir / repo_name / "_checkout"
        clone_dir.parent.mkdir(parents=True, exist_ok=True)

        emitter.scanning(repo_name)
        try:
            clone_repo(repo_url, clone_dir, token=git_token, timeout=TIMEOUT_CLONE)
        except (InsecureURLError, GitCloneError) as e:
            log_tail.append(f"[!] {e}")
            emitter.finished(repo_name)
            return [], False

        try:
            html_url = derive_html_url(repo_url)
            try:
                findings = audit_repo(
                    str(clone_dir), llm=llm, escalation_llm=escalation_llm, scan_budget=budget,
                    accepted_risks=accepted_risks, ground_truth=None, max_workers=workers,
                    max_files=max_files, max_chars=max_chars, cancel_event=cancel_event,
                )
            except Exception as e:  # noqa: BLE001 — one repo must not sink the scan
                log_tail.append(f"[!] deep-audit failed ({repo_name}): {e}")
                logger.exception("[!] deep-audit failed")
                findings = []
            for f in findings:
                f.setdefault("repo_full_name", repo_name)
                f.setdefault("repo_html_url", html_url)
            return findings, True
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
            emitter.finished(repo_name)

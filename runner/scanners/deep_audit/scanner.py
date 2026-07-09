"""DeepAuditScanner — reasoning-based vulnerability discovery.

Clones each repo and runs the requested audit *lenses* (broken access control
first) over its handler files: an LLM hunter proposes findings, a skeptic tries
to refute each, a critic grep-checks the citations. Findings the pattern
scanners (semgrep) structurally can't reach — with an exploit chain, cited
evidence, a reproduction, and a concrete fix, ready for the existing UI.

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
from runner.scanners.deep_audit import lenses as _lenses_pkg  # noqa: F401 — registers lenses
from runner.scanners.deep_audit.engine import run_lens
from runner.scanners.deep_audit.lenses.base import Lens, all_lenses, get_lens
from runner.verification.budget import make_deep_audit_budget, verify_concurrency

logger = logging.getLogger(__name__)

_FAILURE_EXIT_CODE = 2
_DEFAULT_MAX_FILES = 40
_DEFAULT_MAX_CHARS = 8000


def _selected_lenses(env: JobEnv) -> list[Lens]:
    raw = (env.get("DEEP_AUDIT_LENSES") or "authz").strip()
    if raw == "*":
        return all_lenses()
    out: list[Lens] = []
    for key in (k.strip() for k in raw.split(",") if k.strip()):
        lens = get_lens(key)
        if lens is not None:
            out.append(lens)
    return out


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
        lenses = _selected_lenses(env)

        # Reasoning audit needs a model and at least one lens; otherwise no-op.
        if not repos or llm is None or not lenses:
            reason = (
                "no GIT_REPOS" if not repos
                else "no LLM configured (deep audit is reasoning-based)" if llm is None
                else "no lenses selected"
            )
            log_tail.append(f"[!] deep audit skipped — {reason}")
            self._write(out_dir, [])
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(exit_code=0, job_dir=out_dir, log_tail=log_tail)

        emitter.starting()
        escalation_llm = build_escalation_llm_client(env)
        budget = make_deep_audit_budget(env)
        workers = verify_concurrency(env)
        model_name = getattr(llm, "_model", "unknown")
        max_files = env.get_int("DEEP_AUDIT_MAX_FILES", _DEFAULT_MAX_FILES)
        max_chars = env.get_int("DEEP_AUDIT_MAX_FILE_CHARS", _DEFAULT_MAX_CHARS)

        all_findings: list[dict] = []
        any_clone_failed = False
        for repo_url in repos:
            if cancel_event is not None and cancel_event.is_set():
                break
            findings, cloned = self._scan_one_repo(
                repo_url, out_dir, cfg.git_token, lenses,
                llm=llm, escalation_llm=escalation_llm, budget=budget,
                workers=workers, model_name=model_name, max_files=max_files,
                max_chars=max_chars, cancel_event=cancel_event, log_tail=log_tail, emitter=emitter,
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
        self, repo_url, out_dir, git_token, lenses, *, llm, escalation_llm, budget,
        workers, model_name, max_files, max_chars, cancel_event, log_tail, emitter,
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
            findings: list[dict] = []
            for lens in lenses:
                if cancel_event is not None and cancel_event.is_set():
                    break
                try:
                    findings.extend(run_lens(
                        str(clone_dir), lens, llm=llm, escalation_llm=escalation_llm,
                        scan_budget=budget, max_files=max_files, max_chars=max_chars,
                        max_workers=workers, model_name=model_name, cancel_event=cancel_event,
                    ))
                except Exception as e:  # noqa: BLE001 — one lens must not sink the scan
                    log_tail.append(f"[!] deep-audit lens {lens.key} failed ({repo_name}): {e}")
                    logger.exception("[!] deep-audit lens failed")
            for f in findings:
                f.setdefault("repo_full_name", repo_name)
                f.setdefault("repo_html_url", html_url)
            return findings, True
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
            emitter.finished(repo_name)

"""AgentScanner — clones each repo, runs agent-security detectors, writes findings.jsonl.

Deterministic and repo-based (mirrors IacScanner): no external tool binary is
required — detection is pure Python over the checkout, so findings do not depend
on a scanner engine being present in the runner image.
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
from runner.scanners.agent.detectors import attach_code_window, scan_repo
from runner.scanners.agent.llm_judge import judge_prose_files
from runner.scanners.base import ExecutionResult
from runner.verification.budget import make_agent_budget

logger = logging.getLogger(__name__)

_FAILURE_EXIT_CODE = 2

# Deterministic rule id that already covers a prose file — no need to also pay
# for an LLM judgment on a case we caught for free.
_MARKER_INJECTION = "AGENT_INSTRUCTION_INJECTION"


@dataclasses.dataclass(frozen=True)
class AgentScanConfig:
    repos: list[str]
    git_token: str | None

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "AgentScanConfig":
        env = JobEnv(job)
        return cls(
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
        )


class AgentScanner:
    SCANNER_TYPE = "agent_scanning"

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

        cfg = AgentScanConfig.from_job(job)
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

        # BYO LLM client + per-scan budget are shared across every repo in the
        # connection so total LLM spend is bounded per scan, not per repo.
        env = JobEnv(job)
        llm = build_llm_client(env)
        escalation_llm = build_escalation_llm_client(env) if llm is not None else None
        budget = make_agent_budget(env) if llm is not None else None

        all_findings: list[dict] = []
        any_clone_failed = False
        for repo_url in repos:
            if cancel_event is not None and cancel_event.is_set():
                break
            findings, cloned = self._scan_one_repo(
                repo_url, out_dir, cfg.git_token, llm, escalation_llm, budget,
                cancel_event, log_tail, emitter,
            )
            any_clone_failed = any_clone_failed or not cloned
            all_findings.extend(findings)

        findings_path = out_dir / "findings.jsonl"
        with findings_path.open("w", encoding="utf-8") as fh:
            for f in all_findings:
                fh.write(json.dumps(f) + "\n")

        register_output(out_dir, findings_path, "_all")
        log_tail.append(
            f"[+] agent scan complete — {len(all_findings)} findings "
            f"across {len(repos)} repo(s)"
        )
        emitter.normalizing()
        write_done_marker(out_dir)
        emitter.done()

        # Surface a failure exit only when every repo failed to clone; partial
        # clone failures are logged but must not sink a multi-repo scan.
        exit_code = 0
        if cancel_event is not None and cancel_event.is_set():
            exit_code = CANCELLED_EXIT_CODE
        elif any_clone_failed and not all_findings:
            exit_code = _FAILURE_EXIT_CODE
        return ExecutionResult(
            exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:]
        )

    def _scan_one_repo(
        self,
        repo_url: str,
        out_dir: Path,
        git_token: str | None,
        llm,
        escalation_llm,
        budget,
        cancel_event: threading.Event | None,
        log_tail: list[str],
        emitter: ProgressEmitter,
    ) -> tuple[list[dict], bool]:
        """Clone + scan a single repo. Returns (stamped findings, cloned_ok).

        Each finding is stamped with this repo's name/html_url so backend ingest
        attaches it to the right asset. The clone tree is always cleaned up.
        """
        repo_name = repo_name_from_url(repo_url)
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        clone_dir = repo_out / "_checkout"

        emitter.scanning(repo_name)
        try:
            clone_repo(repo_url, clone_dir, token=git_token, timeout=TIMEOUT_CLONE)
        except (InsecureURLError, GitCloneError) as e:
            log_tail.append(f"[!] {e}")
            emitter.finished(repo_name)
            return [], False

        try:
            try:
                findings = scan_repo(str(clone_dir))
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] agent detectors error ({repo_name}): {e}")
                logger.exception("[!] agent detectors error")
                findings = []

            # Optional LLM pass: catch fuzzy prose injection the deterministic
            # detectors can't. Runs only when a BYO model is configured; skips
            # files a deterministic marker already flagged.
            if llm is not None:
                already = {f["file"] for f in findings if f.get("check_id") == _MARKER_INJECTION}
                try:
                    findings.extend(judge_prose_files(
                        str(clone_dir), llm=llm, escalation_llm=escalation_llm,
                        scan_budget=budget,
                        cancel_event=cancel_event, skip_files=already,
                    ))
                except Exception as e:  # noqa: BLE001
                    log_tail.append(f"[!] agent LLM judge error ({repo_name}): {e}")
                    logger.exception("[!] agent LLM judge error")

            html_url = derive_html_url(repo_url)
            for f in findings:
                # Stamp the repo so backend ingest can attach the finding to the
                # right asset (mirrors the other scanners' output).
                f.setdefault("repo_full_name", repo_name)
                f.setdefault("repo_html_url", html_url)
                # Attach the source window here — the one point detector and
                # LLM-judge findings converge while the clone still exists — so
                # every agent finding gets a Code preview, not just detector ones
                # (the judge path skips the detectors' _finalize). No-op when a
                # window is already present.
                attach_code_window(f, str(clone_dir))
            return findings, True
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
            emitter.finished(repo_name)

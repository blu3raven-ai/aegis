"""IacScanner — clones each repo, runs checkov, parses results, writes findings.jsonl."""
from __future__ import annotations

import dataclasses
import json
import logging
import shutil
import subprocess
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
    compute_diff_files,
    derive_html_url,
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
from runner.scanners.iac.parse import parse_checkov_results
from runner.scanners.iac.remediation import attach_iac_fixes
from runner.verification.budget import ScanBudget, make_iac_budget
from runner.verification.cache import apply_cache_hit, lookup_cache, verification_input_hash
from runner.verification.verifiers.iac import verify_iac_finding

logger = logging.getLogger(__name__)


TIMEOUT_CHECKOV: float = 600.0
_FAILURE_EXIT_CODE = 2

_IAC_VERIFY_SEVERITIES = {"high", "critical"}


@dataclasses.dataclass(frozen=True)
class IacScanConfig:
    repos: list[str]
    git_token: str | None
    # When SCAN_SCOPE="diff_scoped" AND BASE_SHA is set, findings outside the
    # diff are dropped post-parse. Checkov has no native --include-only flag,
    # so post-filter is the simplest correct path.
    base_sha: str | None
    scan_scope: str

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "IacScanConfig":
        env = JobEnv(job)
        return cls(
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
            base_sha=env.get("BASE_SHA") or None,
            scan_scope=env.get("SCAN_SCOPE", "full_tree"),
        )


class IacScanner:
    SCANNER_TYPE = "iac_scanning"

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
        backend=None,
    ) -> ExecutionResult:
        self._backend = backend
        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        log_tail: list[str] = []

        cfg = IacScanConfig.from_job(job)
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
        escalation_llm = build_escalation_llm_client(env)
        budget = make_iac_budget(env)

        all_findings: list[dict] = []
        any_clone_failed = False
        for repo_url in repos:
            if cancel_event is not None and cancel_event.is_set():
                break
            findings, cloned = self._scan_one_repo(
                repo_url, out_dir, cfg, llm, escalation_llm, budget,
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
            f"[+] iac scan complete — {len(all_findings)} findings "
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
        cfg: "IacScanConfig",
        llm,
        escalation_llm,
        budget: ScanBudget,
        cancel_event: threading.Event | None,
        log_tail: list[str],
        emitter: ProgressEmitter,
    ) -> tuple[list[dict], bool]:
        """Clone + checkov-scan a single repo. Returns (stamped findings, cloned_ok).

        Each finding is stamped with this repo's name/html_url so backend ingest
        attaches it to the right asset. The clone tree is always cleaned up.
        """
        repo_name = repo_name_from_url(repo_url)
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        clone_dir = repo_out / "_checkout"

        emitter.scanning(repo_name)
        try:
            clone_repo(repo_url, clone_dir, token=cfg.git_token, timeout=TIMEOUT_CLONE)
        except (InsecureURLError, GitCloneError) as e:
            log_tail.append(f"[!] {e}")
            emitter.finished(repo_name)
            return [], False

        # Wrap everything from this point in try/finally so the clone tree is
        # always cleaned up — even if findings.jsonl serialization, verification,
        # or any sibling step raises unexpectedly.
        try:
            try:
                raw = _run_checkov(clone_dir, log_tail, cancel_event)
            except ScannerTimeoutError as e:
                log_tail.append(f"[!] checkov timeout ({repo_name}): {e}")
                raw = {"results": {"failed_checks": []}}
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] checkov error ({repo_name}): {e}")
                logger.exception("[!] checkov error")
                raw = {"results": {"failed_checks": []}}

            findings = parse_checkov_results(raw, repo_root=str(clone_dir))

            if cfg.scan_scope == "diff_scoped" and cfg.base_sha:
                try:
                    head_sha_out = subprocess.run(
                        ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
                        capture_output=True, text=True, check=True, timeout=10,
                    ).stdout.strip()
                except subprocess.CalledProcessError:
                    head_sha_out = ""

                if head_sha_out:
                    try:
                        diff_files = set(
                            compute_diff_files(str(clone_dir), cfg.base_sha, head_sha_out)
                        )
                        before = len(findings)
                        findings = [f for f in findings if f.get("file") in diff_files]
                        logger.info(
                            "[+] checkov diff-scoped: %d -> %d findings (diff %d files)",
                            before, len(findings), len(diff_files),
                        )
                    except ValueError as e:
                        logger.warning(
                            "[!] checkov diff resolution failed (%s) - keeping full results", e
                        )

            findings = self._maybe_verify_iac(
                findings=findings,
                repo_root=str(clone_dir),
                llm=llm,
                escalation_llm=escalation_llm,
                scan_budget=budget,
                cancel_event=cancel_event,
            )

            # Deterministic config-hardening patches for pattern-clear checks.
            # Always-on and independent of the LLM verifier above.
            findings = attach_iac_fixes(findings, str(clone_dir))

            html_url = derive_html_url(repo_url)
            for f in findings:
                # Stamp the repo so backend ingest can attach the finding to the
                # right asset (mirrors the other scanners' output).
                f.setdefault("repo_full_name", repo_name)
                # Web URL of the repo so the finding can deep-link back to source.
                f.setdefault("repo_html_url", html_url)
            return findings, True
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
            emitter.finished(repo_name)

    def _maybe_verify_iac(
        self,
        *,
        findings: list[dict],
        repo_root: str,
        llm,
        escalation_llm=None,
        scan_budget: ScanBudget,
        cancel_event: threading.Event | None = None,
    ) -> list[dict]:
        hashes = [verification_input_hash(f) for f in findings]
        cache = (
            lookup_cache(getattr(self, "_backend", None), tool="iac_scanning", hashes=hashes)
            if llm is not None else {}
        )
        out: list[dict] = []
        for f, input_hash in zip(findings, hashes):
            copy = dict(f)
            metadata: dict = copy.setdefault("verification_metadata", {})

            # Honour the outer cancel signal between findings. The verifier
            # itself can spend tens of seconds on LLM round-trips per finding,
            # so a long backlog otherwise ignores the cancel until the whole
            # loop drains.
            if cancel_event is not None and cancel_event.is_set():
                copy["verdict"] = "possible"
                metadata["skipped"] = "cancelled"
                out.append(copy)
                continue

            if llm is None:
                copy["verdict"] = None
                metadata["skipped"] = "llm_disabled"
                out.append(copy)
                continue

            sev = (copy.get("severity") or "").lower()
            if sev not in _IAC_VERIFY_SEVERITIES:
                copy["verdict"] = None
                metadata["skipped"] = "below_severity"
                out.append(copy)
                continue

            cached = cache.get(input_hash)
            if cached is not None:
                apply_cache_hit(copy, cached, input_hash)
                out.append(copy)
                continue

            if not scan_budget.allow():
                copy["verdict"] = "possible"
                metadata["skipped"] = scan_budget.skip_reason
                out.append(copy)
                continue

            try:
                result = verify_iac_finding(
                    finding=copy, repo_root=repo_root, llm=llm,
                    escalation_llm=escalation_llm,
                )
                scan_budget.record(
                    tokens_in=result.tokens_in, tokens_out=result.tokens_out
                )
                copy["verdict"] = result.verdict
                copy["evidence"] = result.evidence
                copy["exploit_chain"] = result.exploit_chain
                meta = dict(result.verification_metadata or {})
                meta["verification_input_hash"] = input_hash
                copy["verification_metadata"] = meta
            except Exception as e:  # noqa: BLE001
                copy["verdict"] = None
                metadata["skipped"] = f"llm_error:{type(e).__name__}"
                logger.exception(
                    "[!] iac verification failed for %s", copy.get("check_id")
                )

            out.append(copy)
        return out


def _run_checkov(
    target: Path,
    log_tail: list[str],
    cancel_event: threading.Event | None,
) -> dict:
    if shutil.which("checkov") is None:
        log_tail.append("[!] checkov not on PATH")
        return {"results": {"failed_checks": []}}

    rc, stdout, stderr = run_tool(
        ["checkov", "-d", str(target), "-o", "json", "--quiet", "--skip-download"],
        timeout=TIMEOUT_CHECKOV,
        cancel_event=cancel_event,
    )

    # Checkov convention: 0 = no findings, 1 = findings present, other = error.
    if rc not in (0, 1):
        log_tail.append(
            f"[!] checkov exit={rc}: {(stderr or '')[:200]}"
        )
        return {"results": {"failed_checks": []}}

    try:
        return json.loads(stdout or "{}")
    except json.JSONDecodeError as e:
        log_tail.append(f"[!] checkov output unparseable: {e}")
        return {"results": {"failed_checks": []}}

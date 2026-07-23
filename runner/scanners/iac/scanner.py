"""IacScanner — clones each repo, runs checkov, parses results, writes findings.jsonl."""
from __future__ import annotations

import dataclasses
import json
import logging
import concurrent.futures
import shutil
import subprocess
import threading
import time
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
    write_findings_jsonl,
)
from runner.scanners._subprocess import (
    CANCELLED_EXIT_CODE,
    ScannerTimeoutError,
    run_tool,
)
from runner.scanners.base import ExecutionResult
from runner.scanners.iac.parse import parse_checkov_results
from runner.scanners.iac.remediation import attach_iac_fixes
from runner.verification.budget import DEFAULT_VERIFY_WORKERS, ScanBudget, make_iac_budget, verify_concurrency
from runner.verification.cache import apply_cache_hit, lookup_cache, verification_input_hash
from runner.verification.ground_truth import build_ground_truth
from runner.verification.verifiers.iac import verify_iac_finding

logger = logging.getLogger(__name__)


TIMEOUT_CHECKOV: float = 600.0
_FAILURE_EXIT_CODE = 2

_IAC_VERIFY_SEVERITIES = {"medium", "high", "critical"}

# Streaming flush cadence: re-ingest the resolved findings after this many new
# verdicts, but no more often than the min interval, so verdicts surface in the
# UI as they land instead of all at completion, without hammering the backend
# on a large scan.
_STREAM_FLUSH_EVERY = 5
_STREAM_MIN_INTERVAL_S = 10.0


def _is_resolved(rec: dict) -> bool:
    """A finding is streamable only once verification has judged it, i.e. it has
    a verdict or any verification_metadata (a real verdict, a cache hit, or a
    skip such as llm_disabled/llm_error). Still-pending findings (no verdict, no
    metadata) are excluded so raw findings never paint before the LLM sees them."""
    return rec.get("verdict") is not None or bool(rec.get("verification_metadata"))


@dataclasses.dataclass(frozen=True)
class IacScanConfig:
    repos: list[str]
    git_token: str | None
    # When SCAN_SCOPE="diff_scoped" AND BASE_SHA is set, findings outside the
    # diff are dropped post-parse. Checkov has no native --include-only flag,
    # so post-filter is the simplest correct path.
    base_sha: str | None
    scan_scope: str
    verify_workers: int = DEFAULT_VERIFY_WORKERS

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "IacScanConfig":
        env = JobEnv(job)
        return cls(
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
            base_sha=env.get("BASE_SHA") or None,
            scan_scope=env.get("SCAN_SCOPE", "full_tree"),
            verify_workers=verify_concurrency(env),
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

        # Accepted-risk carve-outs the backend stamps into the job env as a JSON
        # array. Malformed input falls open to "no carve-outs" rather than aborting.
        try:
            accepted_risks = json.loads(env.get("ACCEPTED_RISKS") or "[]")
        except (TypeError, ValueError):
            accepted_risks = []
        if not isinstance(accepted_risks, list):
            accepted_risks = []

        findings_path = out_dir / "findings.jsonl"

        # Stream partial verdicts to the UI mid-scan: each throttled flush writes
        # the findings-so-far (completed repos + the in-flight repo's snapshot)
        # atomically and re-triggers preview ingest, so findings flip from
        # needs_verify to their real verdict live instead of all at completion.
        # Only worth it when verification will actually run (LLM configured).
        stream = job is not None and bool(env.get("LLM_API_KEY"))
        flush_write_lock = threading.Lock()

        all_findings: list[dict] = []
        any_clone_failed = False

        def _stream_flush(snapshot: list[dict]) -> None:
            # Repos are scanned sequentially, so `all_findings` (completed repos)
            # is stable while the in-flight repo's workers stream their snapshot.
            with flush_write_lock:
                write_findings_jsonl(findings_path, all_findings + snapshot)
            self._preview_ingest_findings(findings_path, job)

        for repo_url in repos:
            if cancel_event is not None and cancel_event.is_set():
                break
            findings, cloned = self._scan_one_repo(
                repo_url, out_dir, cfg, llm, escalation_llm, budget,
                cancel_event, log_tail, emitter, accepted_risks,
                on_progress=_stream_flush if stream else None,
            )
            any_clone_failed = any_clone_failed or not cloned
            all_findings.extend(findings)

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
        accepted_risks: list | None = None,
        on_progress: Callable[[list[dict]], None] | None = None,
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

            # Stamp the repo BEFORE verification so streamed partial findings
            # carry asset attribution for the mid-scan preview ingest.
            html_url = derive_html_url(repo_url)
            for f in findings:
                # Stamp the repo so backend ingest can attach the finding to the
                # right asset (mirrors the other scanners' output).
                f.setdefault("repo_full_name", repo_name)
                # Web URL of the repo so the finding can deep-link back to source.
                f.setdefault("repo_html_url", html_url)

            findings = self._maybe_verify_iac(
                findings=findings,
                repo_root=str(clone_dir),
                llm=llm,
                escalation_llm=escalation_llm,
                scan_budget=budget,
                cancel_event=cancel_event,
                max_workers=cfg.verify_workers,
                accepted_risks=accepted_risks,
                on_progress=on_progress,
            )

            # Deterministic config-hardening patches for pattern-clear checks.
            # Always-on and independent of the LLM verifier above.
            findings = attach_iac_fixes(findings, str(clone_dir))
            return findings, True
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
            emitter.finished(repo_name)

    def _preview_ingest_findings(self, findings_file: Path, job: dict) -> None:
        """Upload the partial findings and trigger a mid-scan preview ingest so
        verdicts surface as verification runs. Best-effort: any failure just
        means the findings appear at completion instead of early."""
        backend = getattr(self, "_backend", None)
        job_id = job.get("jobId")
        if backend is None or not job_id or not findings_file.exists():
            return
        try:
            from runner.clients.uploader import post_to_url

            spec = backend.presign_uploads(job_id, ["findings.jsonl"]).get("findings.jsonl")
            if not spec or post_to_url(findings_file, spec["url"], spec["fields"]) != "ok":
                return
            backend.preview_ingest(job_id)
        except Exception:  # noqa: BLE001
            logger.warning("[!] preview ingest failed (continuing)", exc_info=True)

    def _maybe_verify_iac(
        self,
        *,
        findings: list[dict],
        repo_root: str,
        llm,
        escalation_llm=None,
        scan_budget: ScanBudget,
        cancel_event: threading.Event | None = None,
        max_workers: int = DEFAULT_VERIFY_WORKERS,
        accepted_risks: list | None = None,
        on_progress: Callable[[list[dict]], None] | None = None,
    ) -> list[dict]:
        hashes = [verification_input_hash(f) for f in findings]
        cache = (
            lookup_cache(getattr(self, "_backend", None), tool="iac_scanning", hashes=hashes)
            if llm is not None else {}
        )

        # Resolve the cheap cases inline and verify the rest concurrently — each
        # finding owns its slot in `out`, so workers share only the locked budget.
        out: list[dict] = [dict(f) for f in findings]
        pending: list[int] = []
        for i, (f, input_hash) in enumerate(zip(findings, hashes)):
            copy = out[i]
            metadata: dict = copy.setdefault("verification_metadata", {})

            if cancel_event is not None and cancel_event.is_set():
                copy["verdict"] = "possible"
                metadata["skipped"] = "cancelled"
            elif llm is None:
                copy["verdict"] = None
                metadata["skipped"] = "llm_disabled"
            elif (copy.get("severity") or "").lower() not in _IAC_VERIFY_SEVERITIES:
                copy["verdict"] = None
                metadata["skipped"] = "below_severity"
            elif (cached := cache.get(input_hash)) is not None:
                apply_cache_hit(copy, cached, input_hash)
            else:
                pending.append(i)

        # Advisory ground truth: one recon pass over the findings' files, reused
        # for every pending finding. Skip the round-trip when nothing needs
        # verifying. Fail-open — None means "no hints".
        ground_truth = (
            build_ground_truth(repo_root=repo_root, findings=findings, llm=llm)
            if pending else None
        )

        # Findings stream to the UI finding-by-finding as they clear the LLM, so
        # log the count going in up front and how many resolved at the end.
        logger.info("[+] verifying %d iac findings via LLM", len(pending))

        # Streaming state: a worker assigns its finished record to out[i] as a
        # single atomic reference swap, so a concurrent snapshot only ever sees
        # fully-built records. The counter/throttle are guarded by a lock, but the
        # (slow, network) flush runs outside it.
        flush_lock = threading.Lock()
        flush_state = {"done": 0, "last": 0.0}

        def _verify_one(i: int) -> None:
            input_hash = hashes[i]
            rec = dict(out[i])
            metadata = rec.setdefault("verification_metadata", {})
            # Re-check cancel per worker so a long backlog stops promptly.
            if cancel_event is not None and cancel_event.is_set():
                rec["verdict"] = "possible"
                metadata["skipped"] = "cancelled"
                out[i] = rec
                return
            if not scan_budget.allow():
                rec["verdict"] = "possible"
                metadata["skipped"] = scan_budget.skip_reason
                out[i] = rec
                return
            try:
                result = verify_iac_finding(
                    finding=rec, repo_root=repo_root, llm=llm,
                    escalation_llm=escalation_llm,
                    accepted_risks=accepted_risks, ground_truth=ground_truth,
                )
                scan_budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
                rec["verdict"] = result.verdict
                rec["evidence"] = result.evidence
                rec["exploit_chain"] = result.exploit_chain
                meta = dict(result.verification_metadata or {})
                meta["verification_input_hash"] = input_hash
                rec["verification_metadata"] = meta
            except Exception as e:  # noqa: BLE001
                rec["verdict"] = None
                rec.setdefault("verification_metadata", {})["skipped"] = f"llm_error:{type(e).__name__}"
                logger.exception("[!] iac verification failed for %s", rec.get("check_id"))
            finally:
                out[i] = rec

            if on_progress is None:
                return
            snapshot: list[dict] | None = None
            with flush_lock:
                flush_state["done"] += 1
                now = time.monotonic()
                if flush_state["done"] % _STREAM_FLUSH_EVERY == 0 and now - flush_state["last"] >= _STREAM_MIN_INTERVAL_S:
                    flush_state["last"] = now
                    # Stream only the findings verify has already judged; pending
                    # raw findings stay hidden until their own round-trip completes.
                    snapshot = [rec for rec in out if _is_resolved(rec)]
            if snapshot is not None:
                try:
                    on_progress(snapshot)
                except Exception:  # noqa: BLE001
                    logger.warning("[!] streaming preview flush failed (continuing)", exc_info=True)

        if pending:
            workers = max(1, min(max_workers, len(pending)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(_verify_one, pending))

        logger.info(
            "[+] verified %d/%d iac findings",
            sum(1 for i in pending if out[i].get("verdict") is not None), len(pending),
        )
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

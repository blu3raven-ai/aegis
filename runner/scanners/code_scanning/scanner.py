"""CodeScanningScanner - embedded port of scanners/code-scanning/run.sh.

Per-repo flow: shallow clone -> ``semgrep --sarif`` ->
:mod:`extract_context` to add code-window/imports/file_class metadata ->
:mod:`reachability` call-graph analysis -> finally :mod:`normalize`
aggregates all per-repo SARIF into ``findings.jsonl``. Each per-repo
output file is recorded in ``_manifest.jsonl`` as it's produced, and the
``_done`` marker is written when the run finishes.
"""
from __future__ import annotations

# The per-repo thread pool now lives in _shared.run_per_repo; this import is
# retained as the module-local surface that lets the pool be swapped in tests.
import concurrent.futures
import dataclasses
import json
import logging
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable

from runner.scanners._shared import (
    BaseScanConfig,
    GitCloneError,
    InsecureURLError,
    JobEnv,
    ProgressEmitter,
    TIMEOUT_CLONE,
    TIMEOUT_GIT_QUERY,
    build_escalation_llm_client,
    build_llm_client,
    clone_repo,
    log,
    parse_repos,
    register_output,
    derive_html_url,
    repo_name_from_url,
    run_per_repo,
    write_findings_jsonl,
)
from runner.scanners._subprocess import run_tool
from runner.scanners.base import ExecutionResult
from runner.scanners.code_scanning import (
    extract_context,
    normalize,
    reachability,
)
from runner.verification.budget import DEFAULT_VERIFY_WORKERS, ScanBudget, verify_concurrency
from runner.verification.cache import apply_cache_hit, lookup_cache, verification_input_hash
from runner.verification.ground_truth import build_ground_truth
from runner.sandbox.harness import runtime_verify_enabled
from runner.sandbox.sast_runtime import verify_findings_at_runtime
from runner.scanners.deep_audit.engine import detect_authz_candidates, verify_authz_finding
from runner.verification.pipeline import verify_finding

logger = logging.getLogger(__name__)


# Verification gate runs post-normalize, in-place on findings.jsonl.
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MIN_VERIFY_SEVERITY = 1  # skip 'info'

# Streaming flush cadence: re-ingest the resolved findings after this many new
# verdicts, but no more often than the min interval, so verdicts surface in the
# UI as they land instead of all at completion — without hammering the backend
# on a large scan.
_STREAM_FLUSH_EVERY = 5
_STREAM_MIN_INTERVAL_S = 10.0


def _is_resolved(rec: dict) -> bool:
    """A finding is streamable only once verification has judged it, i.e. it has
    a verdict or any verification_metadata (a real verdict, a cache hit, or a
    skip such as llm_disabled/llm_error). Still-pending findings (no verdict, no
    metadata) are excluded so raw findings never paint before the LLM sees them."""
    return rec.get("verdict") is not None or bool(rec.get("verification_metadata"))


def _build_scan_budget(env: JobEnv) -> ScanBudget:
    return ScanBudget(
        scan_budget=env.get_int("LLM_TOKEN_BUDGET_PER_SCAN", 200000),
        daily_remaining=env.get_int("LLM_DAILY_REMAINING", 1000000),
    )


def _maybe_verify(
    *, findings: list[dict], repo_root: str, llm, escalation_llm=None, scan_budget: ScanBudget,
    backend=None, max_workers: int = DEFAULT_VERIFY_WORKERS, accepted_risks: list | None = None,
    runtime_enabled: bool = False, on_progress: Callable[[list[dict]], None] | None = None,
    authz_repo_root: str | None = None,
) -> list[dict]:
    # Precompute each finding's cache key and, when verification is on, ask the
    # backend which of those were already verified with identical input — those
    # replay for free instead of re-spending tokens.
    hashes = [verification_input_hash(f) for f in findings]
    cache = (
        lookup_cache(backend, tool="code_scanning", hashes=hashes)
        if llm is not None else {}
    )

    # Resolve the cheap cases (disabled / below severity / cache hit) inline and
    # collect the rest — the ones that need an LLM round-trip — to verify
    # concurrently. Each finding owns its own slot in `out`, so workers never
    # touch shared state except the (locked) scan_budget.
    out: list[dict] = [dict(f) for f in findings]
    pending: list[int] = []
    for i, (f, input_hash) in enumerate(zip(findings, hashes)):
        copy = out[i]
        sev = _SEVERITY_ORDER.get((f.get("severity") or "").lower(), 0)

        if llm is None:
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = "llm_disabled"
        elif sev < _MIN_VERIFY_SEVERITY:
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = "below_severity"
        elif (cached := cache.get(input_hash)) is not None:
            apply_cache_hit(copy, cached, input_hash)
        else:
            pending.append(i)

    # Advisory ground truth: one recon pass over the findings' files, reused for
    # every pending finding. Skip the round-trip entirely when nothing needs
    # verifying (all cached / below severity). Fail-open — None means "no hints".
    ground_truth = (
        build_ground_truth(repo_root=repo_root, findings=findings, llm=llm) if pending else None
    )

    # Findings stream to the UI finding-by-finding as they clear the LLM, so log
    # the count going in up front and how many resolved at the end.
    logger.info("[+] verifying %d code findings via LLM", len(pending))

    # Streaming state: a worker assigns its finished record to out[i] as a single
    # atomic reference swap, so a concurrent snapshot only ever sees fully-built
    # records. The counter/throttle are guarded by a lock, but the (slow, network)
    # flush runs outside it so verification isn't serialised on I/O.
    flush_lock = threading.Lock()
    flush_state = {"done": 0, "last": 0.0}

    def _verify_one(i: int) -> None:
        f, input_hash = findings[i], hashes[i]
        rec = dict(out[i])
        if not scan_budget.allow():
            rec["verdict"] = "possible"
            rec.setdefault("verification_metadata", {})["skipped"] = scan_budget.skip_reason
            out[i] = rec
            return
        try:
            # Route by detector: authz candidates (from deep_audit detection) get
            # the authz verifier and resolve against the live checkout root; every
            # other finding is a SAST result verified over repo_root. Both return
            # a VerificationResult, so everything below is identical.
            if f.get("detector") == "deep_audit":
                result = verify_authz_finding(
                    finding=f, repo_root=authz_repo_root or repo_root, llm=llm,
                    escalation_llm=escalation_llm, accepted_risks=accepted_risks,
                    ground_truth=ground_truth,
                )
            else:
                result = verify_finding(
                    finding=f, repo_root=repo_root, llm=llm, escalation_llm=escalation_llm,
                    accepted_risks=accepted_risks, ground_truth=ground_truth,
                    runtime_enabled=runtime_enabled,
                )
            scan_budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
            rec["verdict"] = result.verdict
            rec["evidence"] = result.evidence
            rec["exploit_chain"] = result.exploit_chain
            meta = dict(result.verification_metadata or {})
            # Stamp the key so the next scan can cache-hit this exact input.
            meta["verification_input_hash"] = input_hash
            rec["verification_metadata"] = meta
        except Exception as e:  # noqa: BLE001
            rec["verdict"] = None
            rec.setdefault("verification_metadata", {})["skipped"] = f"llm_error:{type(e).__name__}"
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
                # Stream only the findings verify has already judged; pending raw
                # findings stay hidden until their own LLM round-trip completes.
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
        "[+] verified %d/%d code findings",
        sum(1 for i in pending if out[i].get("verdict") is not None), len(pending),
    )
    return out


# Semgrep + tree-sitter parse untrusted source; scrub credentials before exec.
_CODE_SCAN_DROP_ENV = ("GIT_TOKEN",)

DEFAULT_SEMGREP_RULES_PATH = "/opt/semgrep-rules"

# Recall-first default: scan with the broad semgrep registry packs and let the
# downstream verification layer tune precision. Overridable via RULESETS (custom
# registry refs or on-disk paths) or SEMGREP_RULES_PATH (an air-gapped bundle,
# e.g. the one baked in at DEFAULT_SEMGREP_RULES_PATH).
DEFAULT_REGISTRY_RULESETS = (
    "p/security-audit",
    "p/sql-injection",
    "p/xss",
    "p/command-injection",
    "p/ssrf",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/insecure-transport",
    "p/trailofbits",
)

# Host the default registry packs are fetched from at scan time.
_SEMGREP_REGISTRY_HOST = "semgrep.dev"
_REGISTRY_PROBE_TIMEOUT_S = 4.0


def _registry_reachable(
    host: str = _SEMGREP_REGISTRY_HOST, timeout: float = _REGISTRY_PROBE_TIMEOUT_S
) -> bool:
    """Best-effort TCP reachability check for the semgrep registry.

    The default rule packs are pulled from the registry when a scan runs; a
    runner with no outbound access would otherwise fail the code scan. Probe
    first so the caller can fall back to the bundled rules. Any error (DNS,
    timeout, refused) is treated as unreachable."""
    import socket

    try:
        with socket.create_connection((host, 443), timeout=timeout):
            return True
    except OSError:
        return False


@dataclasses.dataclass(frozen=True)
class CodeScanningConfig(BaseScanConfig):
    repos: list[str]
    git_token: str | None
    rulesets: str
    rules_path: str
    # When SCAN_SCOPE="diff_scoped" AND BASE_SHA is set, semgrep runs only over
    # files changed between BASE_SHA and the repo's HEAD. Empty diff → zero
    # findings, no scanner invocation.
    base_sha: str | None
    scan_scope: str

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "CodeScanningConfig":
        env = JobEnv(job)
        return cls(
            org_label=env.get("ORG_LABEL", "default"),
            run_id=env.get("RUN_ID", str(job.get("jobId", "unknown"))),
            concurrency=max(1, env.get_int("CONCURRENCY", 4)),
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
            rulesets=env.get("RULESETS", ""),
            rules_path=env.get("SEMGREP_RULES_PATH", ""),
            base_sha=env.get("BASE_SHA") or None,
            scan_scope=env.get("SCAN_SCOPE", "full_tree"),
        )


class CodeScanningScanner:
    SCANNER_TYPE = "code_scanning"

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
        backend=None,
    ) -> ExecutionResult:
        self._backend = backend
        cfg = CodeScanningConfig.from_job(job)

        # Authz (deep_audit) detection runs inline per repo while the checkout is
        # live; candidates are stashed here and appended to findings.jsonl after
        # normalize. Checkouts are kept alive through verification (see _post_scan)
        # so both SAST and authz verifiers can ground against the real tree.
        env = JobEnv(job)
        self._authz_llm = build_llm_client(env) if env.get("LLM_API_KEY") else None
        self._authz_escalation = build_escalation_llm_client(env) if self._authz_llm else None
        self._authz_budget = _build_scan_budget(env) if self._authz_llm else None
        self._authz_cancel = cancel_event
        self._authz_candidates: list[dict] = []
        self._authz_lock = threading.Lock()
        self._live_checkouts: list[Path] = []

        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        log_tail: list[str] = []

        repos = cfg.repos
        emitter = ProgressEmitter(on_progress, expected=len(repos))

        # Computed once after the cancel/empty guards (via pre_scan) because
        # _build_config_args may probe the semgrep registry over the network —
        # work that a cancelled or empty scan must not trigger.
        config_args: list[str] = []

        def _pre_scan() -> None:
            nonlocal config_args
            config_args = self._build_config_args(cfg.rulesets, cfg.rules_path)

        def _scan_one(repo_url: str) -> None:
            self._scan_repo(
                repo_url,
                out_dir,
                git_token=cfg.git_token,
                config_args=config_args,
                cancel_event=cancel_event,
                base_sha=cfg.base_sha,
                scan_scope=cfg.scan_scope,
            )

        def _post_scan() -> None:
            try:
                total, errors = normalize.normalize_code_scanning_output(
                    cfg.org_label, out_dir, cfg.run_id
                )
                log_tail.append(
                    f"[+] Normalized {total} code scanning findings ({errors} errors)"
                )
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] Normalization failed: {e}")
                logger.exception("[!] Normalization failed")

            findings_file = out_dir / "findings.jsonl"
            try:
                # Verdicts stream to the UI finding-by-finding as verification
                # clears each one, with no upfront raw dump, so nothing paints before
                # the LLM has judged it. Only worth it when verification will
                # actually run (LLM set).
                if JobEnv(job).get("LLM_API_KEY"):
                    # Fold authz candidates into the same findings.jsonl before the
                    # single verify pass verifies both SAST and authz findings.
                    self._append_authz_candidates(findings_file, log_tail)
                    # LLM verification is the slow, unpredictable phase; tell the UI
                    # it has started (with the finding count) so the progress bar
                    # doesn't read as frozen while generation runs.
                    emitter.verifying(total)

                try:
                    self._verify_findings_file(
                        findings_file, repo_root=str(out_dir), env=JobEnv(job), job=job,
                        authz_repo_root=self._authz_repo_root(),
                    )
                except Exception:  # noqa: BLE001
                    logger.exception("[!] _verify_findings_file failed (continuing)")
                    log_tail.append("[!] verification step failed; findings unverified")
            finally:
                # Checkouts were kept alive through verification for on-disk
                # grounding; reclaim the disk now, even if verify raised.
                for checkout in self._live_checkouts:
                    shutil.rmtree(checkout, ignore_errors=True)

        return run_per_repo(
            items=repos,
            out_dir=out_dir,
            emitter=emitter,
            concurrency=cfg.concurrency,
            cancel_event=cancel_event,
            log_tail=log_tail,
            scan_one=_scan_one,
            pre_scan=_pre_scan,
            post_scan=_post_scan,
        )

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _preview_ingest_findings(self, findings_file: Path, job: dict) -> None:
        """Upload the normalized (unverified) findings and trigger a mid-scan
        preview ingest so they surface before verification. Best-effort — any
        failure just means the findings appear at completion instead of early."""
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

    def _maybe_detect_authz(self, clone_dir: Path, repo_name: str, html_url: str) -> None:
        """Run authz (deep_audit) detection over a live checkout and stash the
        unverified candidates. Best-effort: a detection failure must not sink the
        code scan, so any error is logged and swallowed."""
        if getattr(self, "_authz_llm", None) is None:
            return
        try:
            candidates = detect_authz_candidates(
                str(clone_dir), llm=self._authz_llm, escalation_llm=self._authz_escalation,
                scan_budget=self._authz_budget, cancel_event=self._authz_cancel,
            )
        except Exception:  # noqa: BLE001
            logger.warning("[!] authz detection failed for %s (continuing)", repo_name, exc_info=True)
            return
        if not candidates:
            return
        for c in candidates:
            c.setdefault("repo_full_name", repo_name)
            c.setdefault("repo_html_url", html_url)
        with self._authz_lock:
            self._authz_candidates.extend(candidates)

    def _append_authz_candidates(self, findings_file: Path, log_tail: list[str]) -> None:
        """Append the stashed authz candidates to findings.jsonl (read, extend,
        rewrite atomically) so the single verify pass covers them too. No-op when
        detection found nothing."""
        candidates = getattr(self, "_authz_candidates", [])
        if not candidates:
            return
        existing: list[dict] = []
        if findings_file.exists():
            for line in findings_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    existing.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("[!] skip non-JSON line in %s", findings_file)
        write_findings_jsonl(findings_file, existing + candidates)
        log_tail.append(f"[+] Appended {len(candidates)} authz candidate(s)")

    def _authz_repo_root(self) -> str | None:
        """Resolvable root for authz on-disk grounding during verification.

        ponytail: single-repo (the current reality) resolves against its own
        live checkout so citation grounding works. Multi-repo falls back to None
        (verify uses out_dir); authz still grounds via each finding's embedded
        auth-context. Give each repo its own verify root when multi-repo lands.
        """
        checkouts = getattr(self, "_live_checkouts", [])
        return str(checkouts[0]) if len(checkouts) == 1 else None

    def _verify_findings_file(
        self, findings_file: Path, *, repo_root: str, env: JobEnv,
        job: dict | None = None,
        cancel_event: threading.Event | None = None,
        authz_repo_root: str | None = None,
    ) -> None:
        """Read findings.jsonl, run _maybe_verify, rewrite in place.

        No-op when the file is missing. When the LLM client can't be built
        (no BYO key configured), every finding is marked skipped=llm_disabled.
        When ``job`` is given, verdicts are streamed to the UI mid-pass: each
        throttled flush rewrites the file atomically and re-triggers preview
        ingest, so findings flip from needs_verify to their real verdict live.
        """
        if not findings_file.exists():
            return

        flush_write_lock = threading.Lock()

        def _stream_flush(snapshot: list[dict]) -> None:
            # Atomic rewrite (temp + replace) so a concurrent flush or the reader
            # never sees a half-written file, then re-ingest the partial verdicts.
            with flush_write_lock:
                write_findings_jsonl(findings_file, snapshot)
            if job is not None:
                self._preview_ingest_findings(findings_file, job)

        raw_findings: list[dict] = []
        for line in findings_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                raw_findings.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("[!] skip non-JSON line in %s", findings_file)

        # Accepted-risk carve-outs the backend stamps into the job env as a JSON
        # array. Malformed input falls open to "no carve-outs" rather than aborting.
        try:
            accepted_risks = json.loads(env.get("ACCEPTED_RISKS") or "[]")
        except (TypeError, ValueError):
            accepted_risks = []
        if not isinstance(accepted_risks, list):
            accepted_risks = []

        # Default to the raw findings so a raise anywhere in the verify pass still
        # leaves the full set on disk for the completion ingest; streaming writes
        # only the resolved subset, so we must never leave that as the final state.
        verified = raw_findings
        try:
            verified = _maybe_verify(
                findings=raw_findings,
                repo_root=repo_root,
                llm=build_llm_client(env),
                escalation_llm=build_escalation_llm_client(env),
                scan_budget=_build_scan_budget(env),
                backend=getattr(self, "_backend", None),
                max_workers=verify_concurrency(env),
                accepted_risks=accepted_risks,
                runtime_enabled=runtime_verify_enabled(env.get),
                on_progress=_stream_flush if job is not None else None,
                authz_repo_root=authz_repo_root,
            )

            # Opt-in runtime pass (RUNTIME_VERIFY): actually run the target to resolve
            # any "confirmed IF <question>" findings. Graceful no-op otherwise.
            verified = verify_findings_at_runtime(
                verified, repo_root, env=env, llm=build_llm_client(env),
                cancel_event=cancel_event,
            )
        finally:
            write_findings_jsonl(findings_file, verified)

    @staticmethod
    def _build_config_args(
        rulesets: str,
        rules_path: str,
        registry_reachable: Callable[[], bool] = _registry_reachable,
    ) -> list[str]:
        """Compute semgrep ``--config`` arguments, in precedence order:

          1. ``RULESETS`` — comma-separated registry refs (``p/…``/``r/…``) or
             absolute on-disk paths that exist.
          2. ``rules_path`` (``SEMGREP_RULES_PATH``) — an explicit rules
             directory, e.g. an air-gapped bundle.
          3. Default — the broad registry packs in ``DEFAULT_REGISTRY_RULESETS``,
             or, when the registry is unreachable, the bundled rules at
             ``DEFAULT_SEMGREP_RULES_PATH`` so an offline runner still produces
             code findings instead of failing.
        """
        config_args: list[str] = []
        for raw in (rulesets or "").split(","):
            r = "".join(raw.split())
            if not r:
                continue
            if r.startswith("/"):
                if Path(r).exists():
                    config_args.extend(["--config", r])
            elif r.startswith(("p/", "r/")):
                config_args.extend(["--config", r])
        if config_args:
            return config_args

        if rules_path:
            return ["--config", rules_path]

        if not registry_reachable():
            logger.warning(
                "[!] semgrep registry unreachable; falling back to bundled rules at %s",
                DEFAULT_SEMGREP_RULES_PATH,
            )
            return ["--config", DEFAULT_SEMGREP_RULES_PATH]

        for pack in DEFAULT_REGISTRY_RULESETS:
            config_args.extend(["--config", pack])
        return config_args

    def _scan_repo(
        self,
        repo_url: str,
        out_dir: Path,
        *,
        git_token: str | None,
        config_args: list[str],
        cancel_event: threading.Event | None,
        base_sha: str | None = None,
        scan_scope: str = "full_tree",
    ) -> Path | None:
        repo_name = repo_name_from_url(repo_url)
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        log("scanning", repo_name)

        clone_dir = repo_out / "_checkout"
        if not str(repo_out.resolve()).startswith(str(out_dir.resolve())):
            raise ValueError(f"repo_out escapes out_dir: {repo_out}")
        try:
            clone_repo(
                repo_url,
                clone_dir,
                token=git_token,
                depth=1,
                timeout=TIMEOUT_CLONE,
            )
        except (InsecureURLError, GitCloneError):
            if str(repo_out.resolve()).startswith(str(out_dir.resolve())):
                shutil.rmtree(repo_out, ignore_errors=True)
            log("done", repo_name)
            raise

        # Keep the checkout alive past this method so the verify pass (SAST and
        # authz) can ground against the real tree; _post_scan reclaims it.
        with self._authz_lock:
            self._live_checkouts.append(clone_dir)

        try:
            head_sha = self._read_head_sha(clone_dir, cancel_event)
            (repo_out / "head-sha.txt").write_text(head_sha or "HEAD")

            html_url = derive_html_url(repo_url)
            (repo_out / "html_url.txt").write_text(html_url)

            sarif_file = repo_out / "semgrep.sarif"

            include_files: list[str] | None = None
            if scan_scope == "diff_scoped" and base_sha and head_sha:
                from runner.scanners._shared import compute_diff_files
                try:
                    include_files = compute_diff_files(str(clone_dir), base_sha, head_sha)
                    logger.info(
                        "[+] %s: diff-scoped semgrep (%d files)",
                        repo_name, len(include_files),
                    )
                    if not include_files:
                        # Empty diff → write minimal SARIF and skip semgrep entirely;
                        # passing no --include would otherwise fall back to full-tree.
                        sarif_file.write_text(
                            '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}'
                        )
                        for f in sorted(repo_out.glob("*.json")):
                            register_output(out_dir, f, repo_name)
                        log("done", repo_name)
                        return sarif_file
                except ValueError as e:
                    logger.warning(
                        "[!] %s: diff resolution failed (%s) — falling back to full-tree",
                        repo_name, e,
                    )
                    include_files = None

            ok = self._run_semgrep(
                clone_dir, sarif_file, config_args, cancel_event,
                include_files=include_files,
            )

            if ok and sarif_file.exists() and sarif_file.stat().st_size > 0:
                try:
                    extract_context.extract_context(clone_dir, repo_out)
                except Exception:
                    logger.exception(
                        "[!] extract_context failed for %s", repo_name
                    )

                try:
                    reachability.write_reachability(
                        clone_dir, sarif_file, repo_out / "reachability.json"
                    )
                except Exception:
                    logger.exception(
                        "[!] reachability failed for %s", repo_name
                    )
                    (repo_out / "reachability.json").write_text("{}")

            # Authz (deep_audit) detection over the live checkout; candidates are
            # stashed and folded into findings.jsonl before the single verify pass.
            self._maybe_detect_authz(clone_dir, repo_name, html_url)

            for f in sorted(repo_out.glob("*.json")):
                register_output(out_dir, f, repo_name)

            log("done", repo_name)
            return sarif_file if sarif_file.exists() else None
        except Exception:
            # On failure this repo's checkout is useless to verification; drop it
            # now and unregister so _post_scan doesn't try to clean it twice.
            with self._authz_lock:
                if clone_dir in self._live_checkouts:
                    self._live_checkouts.remove(clone_dir)
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise

    def _run_semgrep(
        self,
        clone_dir: Path,
        sarif_file: Path,
        config_args: list[str],
        cancel_event: threading.Event | None,
        *,
        include_files: list[str] | None = None,
    ) -> bool:
        """Invoke semgrep --sarif. Returns True if a non-empty SARIF was written."""
        from runner.scanners.code_scanning.semgrep import run_semgrep_sarif

        configs: list[str] = []
        it = iter(config_args)
        for arg in it:
            if arg == "--config":
                configs.append(next(it))
        result = run_semgrep_sarif(
            str(clone_dir), sarif_file,
            configs=configs or None,
            include_files=include_files,
        )
        return result is not None

    def _read_head_sha(
        self, clone_dir: Path, cancel_event: threading.Event | None
    ) -> str:
        rc, stdout, _ = run_tool(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            timeout=TIMEOUT_GIT_QUERY,
            cancel_event=cancel_event,
        )
        if rc != 0:
            return ""
        return stdout.strip()

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
from runner.verification.pipeline import verify_finding

logger = logging.getLogger(__name__)


# Verification gate runs post-normalize, in-place on findings.jsonl.
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MIN_VERIFY_SEVERITY = 1  # skip 'info'


def _build_scan_budget(env: JobEnv) -> ScanBudget:
    return ScanBudget(
        scan_budget=env.get_int("LLM_TOKEN_BUDGET_PER_SCAN", 200000),
        daily_remaining=env.get_int("LLM_DAILY_REMAINING", 1000000),
    )


def _maybe_verify(
    *, findings: list[dict], repo_root: str, llm, escalation_llm=None, scan_budget: ScanBudget,
    backend=None, max_workers: int = DEFAULT_VERIFY_WORKERS, accepted_risks: list | None = None,
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
    # Advisory ground truth: one recon pass over the findings' files, reused for
    # every finding this scan. Fail-open — None means "verify without baseline hints".
    ground_truth = build_ground_truth(repo_root=repo_root, findings=findings, llm=llm)

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

    def _verify_one(i: int) -> None:
        f, input_hash, copy = findings[i], hashes[i], out[i]
        if not scan_budget.allow():
            copy["verdict"] = "possible"
            copy.setdefault("verification_metadata", {})["skipped"] = scan_budget.skip_reason
            return
        try:
            result = verify_finding(
                finding=f, repo_root=repo_root, llm=llm, escalation_llm=escalation_llm,
                accepted_risks=accepted_risks, ground_truth=ground_truth,
            )
            scan_budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
            copy["verdict"] = result.verdict
            copy["evidence"] = result.evidence
            copy["exploit_chain"] = result.exploit_chain
            meta = dict(result.verification_metadata or {})
            # Stamp the key so the next scan can cache-hit this exact input.
            meta["verification_input_hash"] = input_hash
            copy["verification_metadata"] = meta
        except Exception as e:  # noqa: BLE001
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = f"llm_error:{type(e).__name__}"

    if pending:
        workers = max(1, min(max_workers, len(pending)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(_verify_one, pending))

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
            # Surface the unverified findings before the slow verification pass so
            # they appear in seconds; verdicts then stream in as verification runs.
            # Only worth it when verification will actually run (LLM configured).
            if JobEnv(job).get("LLM_API_KEY"):
                self._preview_ingest_findings(findings_file, job)

            try:
                self._verify_findings_file(findings_file, repo_root=str(out_dir), env=JobEnv(job))
            except Exception:  # noqa: BLE001
                logger.exception("[!] _verify_findings_file failed (continuing)")
                log_tail.append("[!] verification step failed; findings unverified")

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

    def _verify_findings_file(self, findings_file: Path, *, repo_root: str, env: JobEnv) -> None:
        """Read findings.jsonl, run _maybe_verify, rewrite in place.

        No-op when the file is missing. When the LLM client can't be built
        (no BYO key configured), every finding is marked skipped=llm_disabled.
        """
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

        # Accepted-risk carve-outs the backend stamps into the job env as a JSON
        # array. Malformed input falls open to "no carve-outs" rather than aborting.
        try:
            accepted_risks = json.loads(env.get("ACCEPTED_RISKS") or "[]")
        except (TypeError, ValueError):
            accepted_risks = []
        if not isinstance(accepted_risks, list):
            accepted_risks = []

        verified = _maybe_verify(
            findings=raw_findings,
            repo_root=repo_root,
            llm=build_llm_client(env),
            escalation_llm=build_escalation_llm_client(env),
            scan_budget=_build_scan_budget(env),
            backend=getattr(self, "_backend", None),
            max_workers=verify_concurrency(env),
            accepted_risks=accepted_risks,
        )

        with open(findings_file, "w") as f:
            for finding in verified:
                f.write(json.dumps(finding, separators=(",", ":")) + "\n")

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

            for f in sorted(repo_out.glob("*.json")):
                register_output(out_dir, f, repo_name)

            log("done", repo_name)
            return sarif_file if sarif_file.exists() else None
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)

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

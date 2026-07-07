"""CodeScanningScanner - embedded port of scanners/code-scanning/run.sh.

Per-repo flow: shallow clone -> ``semgrep --sarif`` ->
:mod:`extract_context` to add code-window/imports/file_class metadata ->
:mod:`reachability` call-graph analysis -> finally :mod:`normalize`
aggregates all per-repo SARIF into ``findings.jsonl``. Each per-repo
output file is recorded in ``_manifest.jsonl`` as it's produced, and the
``_done`` marker is written when the run finishes.
"""
from __future__ import annotations

import concurrent.futures
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
    TIMEOUT_CLONE,
    TIMEOUT_GIT_QUERY,
    build_escalation_llm_client,
    build_llm_client,
    clone_repo,
    log_finished,
    log_scanning,
    parse_repos,
    register_output,
    derive_html_url,
    repo_name_from_url,
)
from runner.scanners._subprocess import (
    CANCELLED_EXIT_CODE,
    ScannerTimeoutError,
    run_tool,
)
from runner.scanners.base import ExecutionResult
from runner.scanners.code_scanning import (
    extract_context,
    normalize,
    reachability,
)
from runner.verification.budget import ScanBudget
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
) -> list[dict]:
    out: list[dict] = []
    for f in findings:
        copy = dict(f)
        sev = _SEVERITY_ORDER.get((f.get("severity") or "").lower(), 0)

        if llm is None:
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = "llm_disabled"
            out.append(copy)
            continue

        if sev < _MIN_VERIFY_SEVERITY:
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = "below_severity"
            out.append(copy)
            continue

        if not scan_budget.allow():
            copy["verdict"] = "possible"
            copy.setdefault("verification_metadata", {})["skipped"] = scan_budget.skip_reason
            out.append(copy)
            continue

        try:
            result = verify_finding(
                finding=f, repo_root=repo_root, llm=llm, escalation_llm=escalation_llm,
            )
            scan_budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
            copy["verdict"] = result.verdict
            copy["evidence"] = result.evidence
            copy["exploit_chain"] = result.exploit_chain
            copy["verification_metadata"] = result.verification_metadata
        except Exception as e:  # noqa: BLE001
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = f"llm_error:{type(e).__name__}"

        out.append(copy)
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
    ) -> ExecutionResult:
        cfg = CodeScanningConfig.from_job(job)

        out_dir = Path(job_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        log_tail: list[str] = []

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

        config_args = self._build_config_args(cfg.rulesets, cfg.rules_path)

        def _scan_one(repo_url: str) -> Path | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            repo_name = repo_name_from_url(repo_url)
            emitter.scanning(repo_name)
            try:
                return self._scan_repo(
                    repo_url,
                    out_dir,
                    git_token=cfg.git_token,
                    config_args=config_args,
                    cancel_event=cancel_event,
                    base_sha=cfg.base_sha,
                    scan_scope=cfg.scan_scope,
                )
            except InsecureURLError as e:
                log_tail.append(f"[!] {e}")
                return None
            except GitCloneError as e:
                log_tail.append(f"[!] {e}")
                return None
            except ScannerTimeoutError as e:
                log_tail.append(f"[!] Timeout scanning {repo_url}: {e}")
                return None
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] Repo {repo_url} failed: {e}")
                logger.exception("[!] Repo %s failed", repo_url)
                return None
            finally:
                emitter.finished(repo_name)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=cfg.concurrency
        ) as pool:
            list(pool.map(_scan_one, repos))

        emitter.normalizing()

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

        try:
            findings_file = out_dir / "findings.jsonl"
            self._verify_findings_file(findings_file, repo_root=str(out_dir), env=JobEnv(job))
        except Exception:  # noqa: BLE001
            logger.exception("[!] _verify_findings_file failed (continuing)")
            log_tail.append("[!] verification step failed; findings unverified")

        write_done_marker(out_dir)
        emitter.done()

        exit_code = 0
        if cancel_event is not None and cancel_event.is_set():
            exit_code = CANCELLED_EXIT_CODE
        return ExecutionResult(
            exit_code=exit_code, job_dir=out_dir, log_tail=log_tail[-50:]
        )

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

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

        verified = _maybe_verify(
            findings=raw_findings,
            repo_root=repo_root,
            llm=build_llm_client(env),
            escalation_llm=build_escalation_llm_client(env),
            scan_budget=_build_scan_budget(env),
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
        log_scanning(repo_name)

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
            log_finished(repo_name)
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
                        log_finished(repo_name)
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

            log_finished(repo_name)
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

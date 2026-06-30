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

from runner.scanners._argus import argus_configured, verify_via_argus
from runner.scanners._manifest import write_done_marker
from runner.scanners._shared import (
    BaseScanConfig,
    GitCloneError,
    InsecureURLError,
    JobEnv,
    ProgressEmitter,
    TIMEOUT_CLONE,
    TIMEOUT_GIT_QUERY,
    clone_repo,
    log_finished,
    log_scanning,
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


def _build_llm_client(env: JobEnv):
    """Construct an LLM client from job env or return None if BYO key isn't configured.

    The backend ships LLM_API_KEY (and friends) inside job['envVars'], not the
    runner process environment, so JobEnv.get is the only correct read path.
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


def _build_scan_budget(env: JobEnv) -> ScanBudget:
    return ScanBudget(
        scan_budget=env.get_int("LLM_TOKEN_BUDGET_PER_SCAN", 200000),
        daily_remaining=env.get_int("LLM_DAILY_REMAINING", 1000000),
    )


def _maybe_verify(
    *, findings: list[dict], repo_root: str, llm, scan_budget: ScanBudget,
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
            result = verify_finding(finding=f, repo_root=repo_root, llm=llm)
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
            rules_path=env.get("SEMGREP_RULES_PATH", DEFAULT_SEMGREP_RULES_PATH),
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

        if argus_configured(env):
            verified = verify_via_argus(
                scanner="code_scanning",
                findings=raw_findings,
                repo_root=repo_root,
                env=env,
            )
        else:
            verified = _maybe_verify(
                findings=raw_findings,
                repo_root=repo_root,
                llm=_build_llm_client(env),
                scan_budget=_build_scan_budget(env),
            )

        with open(findings_file, "w") as f:
            for finding in verified:
                f.write(json.dumps(finding, separators=(",", ":")) + "\n")

    @staticmethod
    def _build_config_args(rulesets: str, default_rules_path: str) -> list[str]:
        """Compute semgrep ``--config`` arguments.

        Mirrors the bash original (run.sh):
          - If ``RULESETS`` is empty, use the bundled rules path.
          - Otherwise, for each comma-separated entry, absolute paths that
            exist on disk pass through directly; named entries fall back to
            the bundled rules path.
          - If after parsing we have no custom rules, use bundled.
        """
        config_args: list[str] = []
        use_bundled = False

        if not rulesets:
            use_bundled = True
        else:
            for raw in rulesets.split(","):
                r = "".join(raw.split())
                if not r:
                    continue
                if r.startswith("/") and Path(r).exists():
                    config_args.extend(["--config", r])
                else:
                    use_bundled = True

        if use_bundled or not config_args:
            config_args.extend(["--config", default_rules_path])
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
        try:
            clone_repo(
                repo_url,
                clone_dir,
                token=git_token,
                depth=1,
                timeout=TIMEOUT_CLONE,
            )
        except (InsecureURLError, GitCloneError):
            shutil.rmtree(repo_out, ignore_errors=True)
            log_finished(repo_name)
            raise

        try:
            head_sha = self._read_head_sha(clone_dir, cancel_event)
            (repo_out / "head-sha.txt").write_text(head_sha or "HEAD")

            html_url = self._derive_html_url(repo_url)
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

    @staticmethod
    def _derive_html_url(repo_url: str) -> str:
        """Strip credentials and ``.git`` suffix to derive the web URL.

        Mirrors the bash ``sed`` pipeline in run.sh.
        """
        url = repo_url
        # strip any embedded user-info between scheme and host
        if url.startswith("https://") and "@" in url[len("https://"):].split("/", 1)[0]:
            scheme, rest = url.split("://", 1)
            host_path = rest.split("@", 1)[1]
            url = f"{scheme}://{host_path}"
        if url.endswith(".git"):
            url = url[:-4]
        return url

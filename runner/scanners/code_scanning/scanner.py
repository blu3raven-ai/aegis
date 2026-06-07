"""CodeScanningScanner - embedded port of scanners/code-scanning/run.sh.

Per-repo flow: shallow clone -> ``opengrep scan`` (SARIF + dataflow) ->
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
    TIMEOUT_OPENGREP,
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
    joern_adapter,
    normalize,
    reachability,
)

logger = logging.getLogger(__name__)


# Opengrep + tree-sitter parse untrusted source; scrub credentials before exec.
_CODE_SCAN_DROP_ENV = ("GIT_TOKEN",)

# Opengrep convention: rc=1 means "findings present", anything > 1 is a real error.
_OPENGREP_FINDINGS_RC = 1

DEFAULT_SEMGREP_RULES_PATH = "/opt/semgrep-rules"


@dataclasses.dataclass(frozen=True)
class CodeScanningConfig(BaseScanConfig):
    repos: list[str]
    git_token: str | None
    rulesets: str
    rules_path: str

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
        )


class CodeScanningScanner:
    SCANNER_TYPE = "code-scanning"

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

    @staticmethod
    def _build_config_args(rulesets: str, default_rules_path: str) -> list[str]:
        """Compute opengrep ``--config`` arguments.

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

            sarif_file = repo_out / "opengrep.json"
            ok = self._run_opengrep(
                clone_dir, sarif_file, config_args, cancel_event
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

            joern_findings_path = repo_out / "joern_findings.json"
            try:
                joern_result = joern_adapter.run(
                    repo_path=clone_dir,
                    workdir=repo_out / "_joern_work",
                )
                joern_findings_path.write_text(
                    json.dumps({
                        "status": joern_result.status,
                        "findings": joern_result.findings,
                    })
                )
            except Exception:
                logger.exception("[!] joern adapter raised for %s", repo_name)
                joern_findings_path.write_text(
                    json.dumps({"status": "failed: adapter raised", "findings": []})
                )

            for f in sorted(repo_out.glob("*.json")):
                register_output(out_dir, f, repo_name)

            log_finished(repo_name)
            return sarif_file if sarif_file.exists() else None
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
            shutil.rmtree(repo_out / "_joern_work", ignore_errors=True)

    def _run_opengrep(
        self,
        clone_dir: Path,
        sarif_file: Path,
        config_args: list[str],
        cancel_event: threading.Event | None,
    ) -> bool:
        if shutil.which("opengrep") is None:
            logger.warning(
                "[!] opengrep not on PATH - skipping %s", sarif_file.parent.name
            )
            return False
        args = [
            "opengrep",
            "scan",
            *config_args,
            "--sarif",
            "--dataflow-traces",
            "-o",
            str(sarif_file),
            "--jobs",
            "4",
            "--no-git-ignore",
            str(clone_dir),
        ]
        rc, _, stderr = run_tool(
            args,
            timeout=TIMEOUT_OPENGREP,
            drop_env=_CODE_SCAN_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc > _OPENGREP_FINDINGS_RC:
            logger.warning(
                "[!] Opengrep exited with code %d for %s: %s",
                rc,
                sarif_file.parent.name,
                (stderr or "")[-500:].strip(),
            )

        if sarif_file.exists() and sarif_file.stat().st_size == 0:
            sarif_file.unlink()
            return False
        return sarif_file.exists()

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

"""SecretsScanner - embedded port of scanners/secrets/run.sh.

Per-repo flow (selected by ``SCAN_DEPTH``):

* ``light``    - shallow clone -> ``trufflehog filesystem``
* ``deep``     - full clone -> ``trufflehog git`` (optionally ``--since-commit``)

Per-repo work runs through a ThreadPoolExecutor; outputs are normalised into
``findings.jsonl`` and the ``_done`` manifest marker is written.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import json
import logging
import os
import re
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
    ScannerConfigError,
    TIMEOUT_CLONE,
    TIMEOUT_GIT_QUERY,
    TIMEOUT_TRUFFLEHOG,
    clone_repo,
    compute_diff_files,
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
from runner.scanners.secrets import normalize
from runner.verification.budget import ScanBudget
from runner.verification.pipeline import verify_secret_finding

logger = logging.getLogger(__name__)


# Secrets tooling pulls in untrusted source; scrub credentials before exec.
_SECRETS_TOOL_DROP_ENV = ("GIT_TOKEN",)

SCAN_DEPTH_LIGHT = "light"
SCAN_DEPTH_DEEP = "deep"
SUPPORTED_SCAN_DEPTHS = {SCAN_DEPTH_LIGHT, SCAN_DEPTH_DEEP}
_UNSUPPORTED_DEPTH_EXIT_CODE = 2

_START_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclasses.dataclass(frozen=True)
class SecretsScanConfig(BaseScanConfig):
    repos: list[str]
    git_token: str | None
    scan_depth: str
    start_date: str
    # When SCAN_SCOPE="diff_scoped" AND BASE_SHA is set, deep-mode trufflehog
    # runs only over commits since BASE_SHA via --since-commit. Filesystem
    # (light) mode has no native diff flag and ignores these fields.
    base_sha: str | None
    scan_scope: str

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "SecretsScanConfig":
        env = JobEnv(job)
        scan_depth = env.get("SCAN_DEPTH", SCAN_DEPTH_LIGHT).lower()
        if scan_depth not in SUPPORTED_SCAN_DEPTHS:
            raise ScannerConfigError(
                f"[!] SCAN_DEPTH={scan_depth!r} is not implemented in the "
                f"embedded scanner. Supported: {sorted(SUPPORTED_SCAN_DEPTHS)}."
            )
        start_date = env.get("SCAN_START_DATE", "")
        if (
            scan_depth == SCAN_DEPTH_DEEP
            and start_date
            and not _START_DATE_RE.match(start_date)
        ):
            raise ScannerConfigError(
                f"[!] SCAN_START_DATE={start_date!r} must be YYYY-MM-DD"
            )
        return cls(
            org_label=env.get("ORG_LABEL", "default"),
            run_id=env.get("RUN_ID", str(job.get("jobId", "unknown"))),
            concurrency=max(1, env.get_int("CONCURRENCY", 4)),
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
            scan_depth=scan_depth,
            start_date=start_date,
            base_sha=env.get("BASE_SHA") or None,
            scan_scope=env.get("SCAN_SCOPE", "full_tree"),
        )


class SecretsScanner:
    SCANNER_TYPE = "secrets"

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

        try:
            cfg = SecretsScanConfig.from_job(job)
        except ScannerConfigError as exc:
            message = str(exc)
            logger.error(message)
            log_tail = [message]
            emitter = ProgressEmitter(on_progress, expected=0)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=_UNSUPPORTED_DEPTH_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail,
            )

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
                    scan_depth=cfg.scan_depth,
                    start_date=cfg.start_date,
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
            total, errors = normalize.normalize_secrets_output(
                cfg.org_label, out_dir, cfg.run_id
            )
            log_tail.append(
                f"[+] Normalized {total} secrets findings ({errors} errors)"
            )
        except Exception as e:  # noqa: BLE001
            log_tail.append(f"[!] Normalization failed: {e}")
            logger.exception("[!] Normalization failed")

        try:
            findings_file = out_dir / "findings.jsonl"
            self._verify_findings_file(findings_file, repo_root=str(out_dir))
        except Exception:  # noqa: BLE001
            logger.exception("[!] _verify_findings_file failed (continuing)")
            log_tail.append("[!] secret verification failed; findings unverified")

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

    def _verify_findings_file(self, findings_file: Path, *, repo_root: str) -> None:
        """Read findings.jsonl, run _maybe_verify_secrets, rewrite in place.

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

        verified = _maybe_verify_secrets(
            findings=raw_findings,
            repo_root=repo_root,
            llm=_build_llm_client(),
            scan_budget=_build_scan_budget(),
        )

        with open(findings_file, "w") as f:
            for finding in verified:
                f.write(json.dumps(finding, separators=(",", ":")) + "\n")

    def _scan_repo(
        self,
        repo_url: str,
        out_dir: Path,
        *,
        git_token: str | None,
        scan_depth: str,
        start_date: str,
        cancel_event: threading.Event | None,
        base_sha: str | None = None,
        scan_scope: str = "full_tree",
    ) -> Path | None:
        repo_name = repo_name_from_url(repo_url)
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        log_scanning(repo_name)

        clone_dir = repo_out / "_checkout"
        # Light: shallow clone for trufflehog filesystem mode.
        # Deep: full history for trufflehog git.
        clone_depth: int | None = 1 if scan_depth == SCAN_DEPTH_LIGHT else None
        try:
            clone_repo(
                repo_url,
                clone_dir,
                token=git_token,
                depth=clone_depth,
                timeout=TIMEOUT_CLONE,
            )
        except (InsecureURLError, GitCloneError):
            shutil.rmtree(repo_out, ignore_errors=True)
            log_finished(repo_name)
            raise

        try:
            produced: list[Path] = []

            if scan_depth == SCAN_DEPTH_LIGHT:
                produced.extend(
                    self._scan_trufflehog_filesystem(
                        clone_dir,
                        repo_out,
                        cancel_event,
                        base_sha=base_sha,
                        scan_scope=scan_scope,
                    )
                )
            elif scan_depth == SCAN_DEPTH_DEEP:
                produced.extend(
                    self._scan_trufflehog_git(
                        clone_dir,
                        repo_out,
                        start_date,
                        cancel_event,
                        base_sha=base_sha,
                        scan_scope=scan_scope,
                    )
                )
            self._cleanup_empty_results(repo_out)

            for f in sorted(repo_out.glob("*.json")):
                register_output(out_dir, f, repo_name)

            log_finished(repo_name)
            return produced[0] if produced and produced[0].exists() else None
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)

    # ---- trufflehog (light) ------------------------------------------

    def _scan_trufflehog_filesystem(
        self,
        clone_dir: Path,
        repo_out: Path,
        cancel_event: threading.Event | None,
        *,
        base_sha: str | None = None,
        scan_scope: str = "full_tree",
    ) -> list[Path]:
        if shutil.which("trufflehog") is None:
            logger.warning("[!] trufflehog not on PATH - skipping %s", repo_out.name)
            return []
        output = repo_out / "trufflehog.json"
        rc, stdout, stderr = run_tool(
            [
                "trufflehog",
                "filesystem",
                str(clone_dir),
                "--no-update",
                "--results=verified,unverified,unknown",
                "--json",
            ],
            timeout=TIMEOUT_TRUFFLEHOG,
            drop_env=_SECRETS_TOOL_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc != 0 and not stdout:
            logger.warning(
                "[!] trufflehog filesystem failed (exit %d) for %s: %s",
                rc,
                repo_out.name,
                (stderr or "")[:200],
            )

        head_sha = self._read_head_sha(clone_dir, cancel_event)

        if stdout and scan_scope == "diff_scoped":
            findings: list[dict] = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            try:
                findings = _apply_diff_scope(
                    findings=findings,
                    clone_dir=str(clone_dir),
                    base_sha=base_sha,
                    head_sha=head_sha,
                )
            except ValueError as e:
                logger.warning(
                    "[!] trufflehog diff resolution failed (%s) - keeping full results", e
                )
            stdout = "\n".join(json.dumps(f, separators=(",", ":")) for f in findings)

        if stdout:
            output.write_text(self._inject_head_sha(stdout, head_sha))
        else:
            output.write_text("")
        return [output]

    def _scan_trufflehog_git(
        self,
        clone_dir: Path,
        repo_out: Path,
        start_date: str,
        cancel_event: threading.Event | None,
        *,
        base_sha: str | None = None,
        scan_scope: str = "full_tree",
    ) -> list[Path]:
        if shutil.which("trufflehog") is None:
            logger.warning("[!] trufflehog not on PATH - skipping %s", repo_out.name)
            return []
        output = repo_out / "trufflehog.json"

        # diff-scoped PR runs anchor on the PR base; start-date anchoring is
        # the older retention-window mode. PR base wins when both are set.
        anchor_commit = ""
        if scan_scope == "diff_scoped" and base_sha:
            anchor_commit = base_sha
        elif start_date:
            if not self._has_commits_after(clone_dir, start_date, cancel_event):
                output.write_text("[]")
                return [output]
            anchor_commit = self._anchor_commit_before(
                clone_dir, start_date, cancel_event
            )

        args = [
            "trufflehog",
            "git",
            f"file://{clone_dir}",
            "--no-update",
            "--results=verified,unverified,unknown",
            "--json",
        ]
        if anchor_commit:
            args.append(f"--since-commit={anchor_commit}")

        rc, stdout, stderr = run_tool(
            args,
            timeout=TIMEOUT_TRUFFLEHOG,
            drop_env=_SECRETS_TOOL_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc != 0 and not stdout:
            logger.warning(
                "[!] trufflehog git failed (exit %d) for %s: %s",
                rc,
                repo_out.name,
                (stderr or "")[:200],
            )
        output.write_text(stdout or "")
        return [output]

    # ---- shared helpers ----------------------------------------------

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

    def _has_commits_after(
        self,
        clone_dir: Path,
        start_date: str,
        cancel_event: threading.Event | None,
    ) -> bool:
        rc, stdout, _ = run_tool(
            [
                "git",
                "-C",
                str(clone_dir),
                "rev-list",
                f"--after={start_date}",
                "HEAD",
            ],
            timeout=TIMEOUT_GIT_QUERY,
            cancel_event=cancel_event,
        )
        if rc != 0:
            return False
        first = stdout.splitlines()[:1]
        return bool(first and first[0].strip())

    def _anchor_commit_before(
        self,
        clone_dir: Path,
        start_date: str,
        cancel_event: threading.Event | None,
    ) -> str:
        rc, stdout, _ = run_tool(
            [
                "git",
                "-C",
                str(clone_dir),
                "rev-list",
                f"--until={start_date}",
                "HEAD",
            ],
            timeout=TIMEOUT_GIT_QUERY,
            cancel_event=cancel_event,
        )
        if rc != 0:
            return ""
        first = stdout.splitlines()[:1]
        return first[0].strip() if first else ""

    @staticmethod
    def _inject_head_sha(jsonl_text: str, head_sha: str) -> str:
        """Annotate each trufflehog JSONL record with the HEAD SHA.

        Trufflehog's filesystem mode omits git metadata, so the bash original
        appended ``{"Commit": <sha>}`` via jq when running light scans. Lines
        that don't parse as JSON are passed through unchanged.
        """
        if not head_sha:
            return jsonl_text
        out_lines: list[str] = []
        for line in jsonl_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                out_lines.append(stripped)
                continue
            if isinstance(obj, dict):
                obj["Commit"] = head_sha
            out_lines.append(json.dumps(obj, separators=(",", ":")))
        return "\n".join(out_lines) + ("\n" if out_lines else "")

    @staticmethod
    def _cleanup_empty_results(repo_out: Path) -> None:
        """Drop ``.json`` outputs that are empty or contain ``[]``.

        Mirrors the bash ``cleanup_empty_results`` helper so the manifest
        doesn't gain entries for empty files.
        """
        for json_file in list(repo_out.glob("*.json")):
            try:
                if json_file.stat().st_size == 0:
                    json_file.unlink()
                    continue
                content = json_file.read_text(errors="replace").strip()
                if content == "[]":
                    json_file.unlink()
            except OSError:
                continue


def _apply_diff_scope(
    *,
    findings: list[dict],
    clone_dir: str,
    base_sha: str | None,
    head_sha: str | None,
) -> list[dict]:
    if not (base_sha and head_sha):
        return findings
    diff_files = set(compute_diff_files(clone_dir.rstrip("/"), base_sha, head_sha))
    prefix = clone_dir.rstrip("/") + "/"
    before = len(findings)
    filtered = []
    for f in findings:
        abs_path = (
            f.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("file", "")
        )
        if not abs_path.startswith(prefix):
            # Path outside the clone dir — can't determine scope, so keep it
            # rather than silently dropping a real secret.
            filtered.append(f)
            continue
        rel_path = abs_path[len(prefix):]
        if rel_path in diff_files:
            filtered.append(f)
    logger.info(
        "trufflehog filesystem diff-scope: %d -> %d findings across %d diff files",
        before,
        len(filtered),
        len(diff_files),
    )
    return filtered


def _build_llm_client():
    """Construct an LLM client from env or return None if BYO key isn't configured."""
    from runner.verification.llm_client import LlmClient

    api_key = os.getenv("LLM_API_KEY")
    if not api_key:
        return None
    return LlmClient(
        api_key=api_key,
        api_base_url=os.getenv("LLM_API_BASE_URL", "https://api.openai.com/v1"),
        model=os.getenv("LLM_API_MODEL", "gpt-4o-mini"),
    )


def _build_scan_budget() -> ScanBudget:
    return ScanBudget(
        scan_budget=int(os.getenv("LLM_TOKEN_BUDGET_PER_SCAN", "200000")),
        daily_remaining=int(os.getenv("LLM_DAILY_REMAINING", "1000000")),
    )


def _maybe_verify_secrets(
    *, findings: list[dict], repo_root: str, llm, scan_budget: ScanBudget,
) -> list[dict]:
    out: list[dict] = []
    for f in findings:
        copy = dict(f)

        if llm is None:
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = "llm_disabled"
            out.append(copy)
            continue

        # Provider-verified secrets bypass the budget — auto-confirmed
        if not f.get("verified") and not scan_budget.allow():
            copy["verdict"] = "possible"
            copy.setdefault("verification_metadata", {})["skipped"] = scan_budget.skip_reason
            out.append(copy)
            continue

        try:
            result = verify_secret_finding(finding=f, repo_root=repo_root, llm=llm)
            if not f.get("verified"):
                scan_budget.record(tokens_in=result.tokens_in, tokens_out=result.tokens_out)
            copy["verdict"] = result.verdict
            copy["evidence_json"] = result.evidence
            copy["exploit_chain"] = result.exploit_chain
            copy["verification_metadata"] = result.verification_metadata
        except Exception as e:  # noqa: BLE001
            copy["verdict"] = None
            copy.setdefault("verification_metadata", {})["skipped"] = f"llm_error:{type(e).__name__}"

        out.append(copy)
    return out

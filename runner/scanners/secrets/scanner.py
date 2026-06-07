"""SecretsScanner - embedded port of scanners/secrets/run.sh.

Per-repo flow (selected by ``SCAN_DEPTH``):

* ``light``    - shallow clone -> ``trufflehog filesystem``
* ``deep``     - full clone -> ``trufflehog git`` (optionally ``--since-commit``)
* ``ai_enhanced`` - full clone -> ``betterleaks`` -> in-process context
  enrichment; classification runs once across all repos after the pool drains.

Per-repo work runs through a ThreadPoolExecutor; outputs are normalised into
``findings.jsonl`` and the ``_done`` manifest marker is written.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import json
import logging
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
    TIMEOUT_BETTERLEAKS,
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
from runner.scanners.secrets import classify, enrich_context, normalize

logger = logging.getLogger(__name__)


# Secrets tooling pulls in untrusted source; scrub credentials before exec.
_SECRETS_TOOL_DROP_ENV = ("GIT_TOKEN",)

SCAN_DEPTH_LIGHT = "light"
SCAN_DEPTH_DEEP = "deep"
SCAN_DEPTH_AI = "ai_enhanced"
SUPPORTED_SCAN_DEPTHS = {SCAN_DEPTH_LIGHT, SCAN_DEPTH_DEEP, SCAN_DEPTH_AI}
_UNSUPPORTED_DEPTH_EXIT_CODE = 2

_START_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclasses.dataclass(frozen=True)
class SecretsScanConfig(BaseScanConfig):
    repos: list[str]
    git_token: str | None
    scan_depth: str
    start_date: str

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
            scan_depth in (SCAN_DEPTH_DEEP, SCAN_DEPTH_AI)
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

        # AI classification runs once across every betterleaks_raw.json the
        # ai_enhanced pass emitted - matches the bash batch pattern.
        if cfg.scan_depth == SCAN_DEPTH_AI:
            try:
                count = classify.classify_batch(out_dir)
                log_tail.append(f"[+] Classified {count} secrets findings")
            except Exception as e:  # noqa: BLE001
                log_tail.append(f"[!] AI classification failed: {e}")
                logger.exception("[!] AI classification failed")

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

    def _scan_repo(
        self,
        repo_url: str,
        out_dir: Path,
        *,
        git_token: str | None,
        scan_depth: str,
        start_date: str,
        cancel_event: threading.Event | None,
    ) -> Path | None:
        repo_name = repo_name_from_url(repo_url)
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        log_scanning(repo_name)

        clone_dir = repo_out / "_checkout"
        # Light: shallow single-branch clone is sufficient for trufflehog
        # filesystem mode. Deep/ai_enhanced need full history.
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
                        clone_dir, repo_out, cancel_event
                    )
                )
            elif scan_depth == SCAN_DEPTH_DEEP:
                produced.extend(
                    self._scan_trufflehog_git(
                        clone_dir, repo_out, start_date, cancel_event
                    )
                )
            elif scan_depth == SCAN_DEPTH_AI:
                produced.extend(
                    self._scan_betterleaks(
                        clone_dir, repo_out, start_date, cancel_event
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
    ) -> list[Path]:
        if shutil.which("trufflehog") is None:
            logger.warning("[!] trufflehog not on PATH - skipping %s", repo_out.name)
            return []
        output = repo_out / "trufflehog.json"

        anchor_commit = ""
        if start_date:
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

    # ---- betterleaks (ai_enhanced) -----------------------------------

    def _scan_betterleaks(
        self,
        clone_dir: Path,
        repo_out: Path,
        start_date: str,
        cancel_event: threading.Event | None,
    ) -> list[Path]:
        if shutil.which("betterleaks") is None:
            logger.warning(
                "[!] betterleaks not on PATH - skipping %s", repo_out.name
            )
            return []
        raw = repo_out / "betterleaks_raw.json"
        args = [
            "betterleaks",
            "git",
            str(clone_dir),
            "--report-format",
            "json",
            "--report-path",
            str(raw),
        ]
        if start_date:
            args.extend(["--log-opts", f"--after={start_date}"])

        rc, _, stderr = run_tool(
            args,
            timeout=TIMEOUT_BETTERLEAKS,
            drop_env=_SECRETS_TOOL_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc != 0:
            logger.info(
                "[!] betterleaks exit=%d for %s: %s",
                rc,
                repo_out.name,
                (stderr or "")[:200],
            )

        # Enrich now, while the clone is still on disk.
        if raw.exists() and raw.stat().st_size > 0:
            try:
                enrich_context.enrich_file(raw, clone_dir)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "[!] enrich_context failed for %s: %s", repo_out.name, e
                )
        return [raw]

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

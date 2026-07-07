"""DependenciesScanner — clone each repo, build an SBOM, and register it.

Per-repo work runs through a ThreadPoolExecutor; each repo is cloned, an SBOM
is built (syft + optional cdxgen merge) and registered for upload, then the
_done manifest marker is written. Vulnerability matching happens in the backend
against the OSV mirror — the runner produces SBOMs only.
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
from runner.scanners.dependencies.declared_ranges import (
    annotate_sbom_with_declared_ranges,
    parse_declared_ranges,
)
from runner.scanners._shared import (
    BaseScanConfig,
    JobEnv,
    ProgressEmitter,
    ScannerConfigError,
    TIMEOUT_CDXGEN,
    TIMEOUT_CLONE,
    TIMEOUT_SYFT_REPO,
    clone_repo,
    derive_html_url,
    log,
    parse_repos,
    register_output,
    repo_name_from_url,
    run_per_repo,
)
from runner.scanners._subprocess import run_tool
from runner.scanners.base import ExecutionResult

logger = logging.getLogger(__name__)


# SBOM tools may invoke lockfile install scripts inside untrusted repos —
# scrub credentials before handing control over.
_SBOM_TOOL_DROP_ENV = ("GIT_TOKEN",)

SCAN_MODE_FULL = "full"
SCAN_MODE_SBOM_ONLY = "sbom_only"
SUPPORTED_SCAN_MODES = {
    SCAN_MODE_FULL,
    SCAN_MODE_SBOM_ONLY,
}
DEFERRED_SCAN_MODES: set[str] = set()
_UNSUPPORTED_MODE_EXIT_CODE = 2


@dataclasses.dataclass(frozen=True)
class DependenciesScanConfig(BaseScanConfig):
    repos: list[str]
    git_token: str | None
    scan_mode: str

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> "DependenciesScanConfig":
        env = JobEnv(job)
        scan_mode = env.get("SCAN_MODE", SCAN_MODE_FULL).lower()
        if scan_mode not in SUPPORTED_SCAN_MODES:
            raise ScannerConfigError(
                f"[!] SCAN_MODE={scan_mode!r} is not implemented in the "
                f"embedded scanner. Supported: {sorted(SUPPORTED_SCAN_MODES)}. "
                f"Deferred: {sorted(DEFERRED_SCAN_MODES)}."
            )
        return cls(
            org_label=env.get("ORG_LABEL", "default"),
            run_id=env.get("RUN_ID", str(job.get("jobId", "unknown"))),
            concurrency=max(1, env.get_int("CONCURRENCY", 4)),
            repos=parse_repos(env.get("GIT_REPOS")),
            git_token=env.get("GIT_TOKEN") or None,
            scan_mode=scan_mode,
        )


class DependenciesScanner:
    SCANNER_TYPE = "dependencies_scanning"

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
            cfg = DependenciesScanConfig.from_job(job)
        except ScannerConfigError as exc:
            message = str(exc)
            logger.error(message)
            log_tail = [message]
            emitter = ProgressEmitter(on_progress, expected=0)
            emitter.done()
            write_done_marker(out_dir)
            return ExecutionResult(
                exit_code=_UNSUPPORTED_MODE_EXIT_CODE,
                job_dir=out_dir,
                log_tail=log_tail,
            )

        # Backend-native OSV matching: the runner produces SBOMs only and the
        # backend matches them against the OSV mirror. "full" and "sbom_only"
        # both route to the SBOM-only path.
        return self._run_sbom_only(
            repos=cfg.repos,
            out_dir=out_dir,
            git_token=cfg.git_token,
            concurrency=cfg.concurrency,
            on_progress=on_progress,
            cancel_event=cancel_event,
            log_tail=log_tail,
        )

    def _run_sbom_only(
        self,
        *,
        repos: list[str],
        out_dir: Path,
        git_token: str | None,
        concurrency: int,
        on_progress: Callable[[list[str], dict], None] | None,
        cancel_event: threading.Event | None,
        log_tail: list[str],
    ) -> ExecutionResult:
        """Per-repo clone + SBOM build + register. No findings.jsonl is written."""
        emitter = ProgressEmitter(on_progress, expected=len(repos))

        def _scan_one(repo_url: str) -> None:
            self._scan_repo(
                repo_url,
                out_dir,
                git_token=git_token,
                cancel_event=cancel_event,
            )

        return run_per_repo(
            items=repos,
            out_dir=out_dir,
            emitter=emitter,
            concurrency=concurrency,
            cancel_event=cancel_event,
            log_tail=log_tail,
            scan_one=_scan_one,
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
        cancel_event: threading.Event | None,
    ) -> None:
        repo_name = repo_name_from_url(repo_url)
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        log("scanning", repo_name)

        clone_dir = repo_out / "_checkout"
        clone_repo(repo_url, clone_dir, token=git_token, timeout=TIMEOUT_CLONE)

        head_sha = self._read_head_sha(clone_dir, cancel_event)
        (repo_out / "head-sha.txt").write_text(head_sha + "\n")
        # Repo web URL sidecar: deps findings are built backend-side from the
        # SBOM, so the backend reads this to deep-link them to their source.
        (repo_out / "html_url.txt").write_text(derive_html_url(repo_url) + "\n")

        syft_sbom = repo_out / "syft-sbom.cdx.json"
        cdxgen_sbom = repo_out / "cdxgen-sbom.cdx.json"
        merged_sbom = repo_out / "sbom.cdx.json"

        syft_ok = self._run_syft(clone_dir, syft_sbom, cancel_event)
        cdxgen_ok = self._run_cdxgen(clone_dir, cdxgen_sbom, cancel_event)

        if syft_ok and cdxgen_ok:
            if not self._merge_sboms(syft_sbom, cdxgen_sbom, merged_sbom):
                shutil.copy(syft_sbom, merged_sbom)
        elif syft_ok:
            shutil.copy(syft_sbom, merged_sbom)
        elif cdxgen_ok:
            shutil.copy(cdxgen_sbom, merged_sbom)
        else:
            logger.warning(
                "[!] Both SBOM generators failed for %s - skipping", repo_name
            )
            log("done", repo_name)
            shutil.rmtree(clone_dir, ignore_errors=True)
            return

        # Additive enrichment: stamp each direct dep's declared range and
        # manifest location onto its SBOM component while the manifests are
        # still on disk. The broad except is intentional — capture must never
        # fail the scan.
        try:
            decls = parse_declared_ranges(clone_dir)
            if decls:
                n = annotate_sbom_with_declared_ranges(merged_sbom, decls, clone_dir)
                logger.debug(
                    "[+] stamped declared ranges on %d components for %s",
                    n,
                    repo_name,
                )
        except Exception:  # noqa: BLE001
            logger.warning(
                "[!] declared-range capture failed for %s — continuing",
                repo_name,
                exc_info=True,
            )

        register_output(out_dir, merged_sbom, repo_name)

        log("done", repo_name)
        shutil.rmtree(clone_dir, ignore_errors=True)

    def _read_head_sha(
        self, clone_dir: Path, cancel_event: threading.Event | None
    ) -> str:
        rc, stdout, _ = run_tool(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            timeout=30.0,
            cancel_event=cancel_event,
        )
        if rc != 0:
            return "unknown"
        return stdout.strip() or "unknown"

    def _run_syft(
        self,
        target: Path,
        output: Path,
        cancel_event: threading.Event | None,
    ) -> bool:
        if shutil.which("syft") is None:
            return False
        rc, stdout, stderr = run_tool(
            [
                "syft",
                str(target),
                "-o",
                "cyclonedx-json",
                "--parallelism",
                "2",
            ],
            timeout=TIMEOUT_SYFT_REPO,
            drop_env=_SBOM_TOOL_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc != 0:
            logger.warning("[!] Syft failed: %s", (stderr or "")[:200])
            return False
        output.write_text(stdout)
        self._tag_sbom_source(output, "syft")
        return True

    def _run_cdxgen(
        self,
        target: Path,
        output: Path,
        cancel_event: threading.Event | None,
    ) -> bool:
        if shutil.which("cdxgen") is None:
            return False
        rc, _, stderr = run_tool(
            ["cdxgen", "-o", str(output), str(target), "--no-recurse"],
            timeout=TIMEOUT_CDXGEN,
            drop_env=_SBOM_TOOL_DROP_ENV,
            cancel_event=cancel_event,
        )
        if rc != 0 or not output.exists() or output.stat().st_size == 0:
            logger.warning("[!] cdxgen failed: %s", (stderr or "")[:200])
            return False
        self._tag_sbom_source(output, "cdxgen")
        return True

    def _merge_sboms(
        self, syft_sbom: Path, cdxgen_sbom: Path, merged: Path
    ) -> bool:
        if shutil.which("cyclonedx") is None:
            return False
        rc, _, _ = run_tool(
            [
                "cyclonedx",
                "merge",
                "--input-files",
                str(syft_sbom),
                str(cdxgen_sbom),
                "--output-file",
                str(merged),
                "--output-format",
                "json",
            ],
            timeout=120.0,
            env={"DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "true"},
            drop_env=_SBOM_TOOL_DROP_ENV,
        )
        return rc == 0 and merged.exists() and merged.stat().st_size > 0

    def _tag_sbom_source(self, sbom_file: Path, tool_name: str) -> None:
        """Append a {"name": "scanner:source", "value": <tool>} property to every
        component — mirrors the jq one-liner in the bash original."""
        if not sbom_file.exists() or sbom_file.stat().st_size == 0:
            return
        try:
            data = json.loads(sbom_file.read_text())
        except (json.JSONDecodeError, OSError):
            return
        components = data.get("components") or []
        for comp in components:
            props = comp.get("properties") or []
            props.append({"name": "scanner:source", "value": tool_name})
            comp["properties"] = props
        try:
            sbom_file.write_text(json.dumps(data, separators=(",", ":")))
        except OSError:
            pass

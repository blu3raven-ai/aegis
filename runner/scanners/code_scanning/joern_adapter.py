"""Joern adapter — runs interprocedural taint queries via joern-cli.

Builds a Code Property Graph (CPG) from the repo once per scan and runs the
curated CWE-tagged query scripts shipped in joern_queries/. Each query emits
findings as JSON lines; this module normalizes them to the Aegis finding
schema and tags them with engine=joern + dataflow_trace.

Failures (build crash, query timeout, malformed output) are logged and
return an empty findings list — never raise — so Opengrep results still
ship even when Joern misbehaves.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from runner.metrics import (
    joern_cpg_build_duration_seconds,
    joern_findings_total,
    joern_scan_duration_seconds,
    joern_scans_total,
)

logger = logging.getLogger(__name__)

_QUERIES_DIR = Path(__file__).parent / "joern_queries"
_DEFAULT_MEMORY_MB = 4096
_DEFAULT_TIMEOUT_SECONDS = 600  # 10 minutes total for CPG build + all queries

# v1 language scope. Joern supports more; these have the strongest frontends.
_SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java"}

# Vendored/build dirs to skip during language detection.
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
}


@dataclasses.dataclass
class JoernResult:
    findings: list[dict[str, Any]]
    status: str  # "ok" / "skipped: <reason>" / "failed: <reason>"


def run(repo_path: Path, workdir: Path) -> JoernResult:
    start = time.monotonic()

    if not _has_supported_language(repo_path):
        joern_scans_total.labels(outcome="skipped").inc()
        return JoernResult(findings=[], status="skipped: no supported language")

    workdir.mkdir(parents=True, exist_ok=True)
    cpg_path = workdir / "cpg.bin"
    memory_mb = int(os.environ.get("JOERN_MAX_MEMORY_MB", _DEFAULT_MEMORY_MB))
    timeout = int(os.environ.get("JOERN_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_SECONDS))
    deadline = time.monotonic() + timeout

    parse_cmd = [
        "joern-parse",
        f"-J-Xmx{memory_mb}m",
        "--output", str(cpg_path),
        str(repo_path),
    ]
    parse_remaining = max(1, int(deadline - time.monotonic()))
    cpg_start = time.monotonic()
    try:
        result = _run_subprocess(parse_cmd, timeout=parse_remaining)
    except subprocess.TimeoutExpired:
        joern_cpg_build_duration_seconds.observe(time.monotonic() - cpg_start)
        joern_scans_total.labels(outcome="timeout").inc()
        logger.warning("[!] joern-parse timeout after %ds", parse_remaining)
        return JoernResult(findings=[], status=f"failed: timeout after {parse_remaining}s")
    except (subprocess.SubprocessError, OSError) as exc:
        joern_cpg_build_duration_seconds.observe(time.monotonic() - cpg_start)
        joern_scans_total.labels(outcome="failed").inc()
        logger.exception("[!] joern-parse crashed")
        return JoernResult(findings=[], status=f"failed: {exc}")

    joern_cpg_build_duration_seconds.observe(time.monotonic() - cpg_start)

    if result.returncode != 0:
        joern_scans_total.labels(outcome="failed").inc()
        logger.warning("[!] joern-parse exit=%d stderr=%s", result.returncode, result.stderr[:500])
        return JoernResult(findings=[], status=f"failed: joern-parse exit {result.returncode}")

    all_findings: list[dict[str, Any]] = []
    query_paths = sorted(_QUERIES_DIR.glob("*.sc"))
    total_queries = len(query_paths)
    failed_count = 0
    for query_path in query_paths:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            logger.warning("[!] joern timeout budget exhausted; skipping remaining queries")
            break

        out_path = workdir / f"{query_path.stem}.jsonl"
        query_cmd = [
            "joern",
            f"-J-Xmx{memory_mb}m",
            "--script", str(query_path),
            "--param", f"cpgFile={cpg_path}",
            "--param", f"outFile={out_path}",
        ]
        try:
            result = _run_subprocess(query_cmd, timeout=remaining)
        except subprocess.TimeoutExpired:
            logger.warning("[!] joern query %s timeout", query_path.name)
            failed_count += 1
            continue
        except (subprocess.SubprocessError, OSError):
            logger.exception("[!] joern query %s crashed", query_path.name)
            failed_count += 1
            continue

        if result.returncode != 0:
            logger.warning("[!] joern query %s exit=%d", query_path.name, result.returncode)
            failed_count += 1
            continue

        try:
            entries = _read_query_output(out_path)
        except Exception:  # noqa: BLE001 — json.loads + I/O can raise many types
            logger.exception("[!] failed to parse joern output %s", out_path)
            failed_count += 1
            continue

        for entry in entries:
            try:
                all_findings.append(_normalize(entry))
            except Exception:  # noqa: BLE001 — defensive: skip a single bad entry, keep the rest
                logger.exception("[!] failed to normalize joern entry from %s", query_path.name)
                continue

    if failed_count == 0:
        status = "ok"
    else:
        status = f"ok: {failed_count}/{total_queries} queries failed"

    joern_scan_duration_seconds.observe(time.monotonic() - start)
    for finding in all_findings:
        cwe = finding.get("cwe", "UNKNOWN") or "UNKNOWN"
        joern_findings_total.labels(cwe=cwe).inc()
    joern_scans_total.labels(outcome="ok").inc()

    return JoernResult(findings=all_findings, status=status)


def _has_supported_language(repo_path: Path) -> bool:
    for ext in _SUPPORTED_EXTENSIONS:
        for path in repo_path.rglob(f"*{ext}"):
            if not any(part in _SKIP_DIRS for part in path.parts):
                return True
    return False


def _run_subprocess(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _read_query_output(out_path: Path) -> list[dict[str, Any]]:
    if not out_path.exists():
        return []
    entries: list[dict[str, Any]] = []
    with out_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def _normalize(entry: dict[str, Any]) -> dict[str, Any]:
    try:
        line = int(entry.get("line", 0))
    except (TypeError, ValueError):
        line = 0
    return {
        "engine": "joern",
        "cwe": entry.get("cwe", ""),
        "file": entry.get("file", ""),
        "line": line,
        "rule_id": entry.get("rule_id", ""),
        "severity": entry.get("severity", "medium"),
        "title": entry.get("title", ""),
        "dataflow_trace": entry.get("dataflow_trace", []),
    }

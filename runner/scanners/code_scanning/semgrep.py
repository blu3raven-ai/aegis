"""Semgrep subprocess wrapper and SARIF/JSON result normalizer."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

# Default: scan against the rule packs pre-cached in the runner image.
# Override via SEMGREP_CONFIGS env var (comma-separated paths or pack names).
_DEFAULT_CONFIG_PATH = "/opt/semgrep-rules"

_PER_FILE_TIMEOUT = 30
_OVERALL_TIMEOUT = 1800


def _resolve_configs() -> list[str]:
    override = os.getenv("SEMGREP_CONFIGS")
    if override:
        return [c.strip() for c in override.split(",") if c.strip()]
    return [_DEFAULT_CONFIG_PATH]


def run_semgrep_sarif(
    repo_root: str,
    sarif_out,
    *,
    configs: list[str] | None = None,
    include_files: list[str] | None = None,
):
    """Invoke semgrep with --sarif. Return the SARIF path on success, None on failure.

    ``include_files=None`` or ``[]`` both mean "no scope restriction (full tree)".
    Callers that know the include list is empty (e.g. empty diff) should
    short-circuit before invoking semgrep, since an unrestricted scan is the
    wrong fallback for that case.
    """
    from pathlib import Path

    sarif_out = Path(sarif_out)
    configs = configs or _resolve_configs()
    cmd = ["semgrep"]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    cmd.extend([
        "--sarif",
        "-o", str(sarif_out),
        "--quiet", "--no-git-ignore",
        "--timeout", str(_PER_FILE_TIMEOUT),
        "--timeout-threshold", "3",
    ])
    if include_files:
        for f in include_files:
            cmd.extend(["--include", f])
    cmd.append(repo_root)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_OVERALL_TIMEOUT)
    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after %ds", _OVERALL_TIMEOUT)
        return None

    if proc.returncode not in (0, 1):
        logger.warning("semgrep exit=%d stderr=%s", proc.returncode, proc.stderr[:500])

    if not sarif_out.exists() or sarif_out.stat().st_size == 0:
        return None
    return sarif_out


def run_semgrep(
    repo_root: str,
    *,
    configs: list[str] | None = None,
    include_files: list[str] | None = None,
) -> dict:
    """Invoke semgrep against repo_root. Return parsed JSON output.

    ``include_files=None`` or ``[]`` both mean "no scope restriction (full tree)".
    Callers that know the include list is empty (e.g. empty diff) should
    short-circuit before invoking semgrep, since an unrestricted scan is the
    wrong fallback for that case.
    """
    configs = configs or _resolve_configs()
    cmd = ["semgrep"]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    cmd.extend([
        "--json", "--quiet", "--no-git-ignore",
        "--timeout", str(_PER_FILE_TIMEOUT),
        "--timeout-threshold", "3",
    ])
    if include_files:
        for f in include_files:
            cmd.extend(["--include", f])
    cmd.append(repo_root)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_OVERALL_TIMEOUT)
    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after %ds", _OVERALL_TIMEOUT)
        return {"results": []}

    # semgrep exit codes: 0 = clean, 1 = findings, 2 = error.
    if proc.returncode not in (0, 1):
        logger.warning("semgrep exit=%d stderr=%s", proc.returncode, proc.stderr[:500])

    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        logger.error("semgrep output unparseable: %s", e)
        return {"results": []}


def parse_semgrep_results(raw: dict, *, repo_root: str) -> list[dict]:
    out: list[dict] = []
    for r in raw.get("results") or []:
        sev_in = (r.get("extra") or {}).get("severity") or ""
        severity = _SEVERITY_MAP.get(sev_in.upper(), "medium")
        path = _normalize_path(r.get("path", ""), repo_root)
        line = int((r.get("start") or {}).get("line") or 1)
        message = (r.get("extra") or {}).get("message") or ""
        snippet = (r.get("extra") or {}).get("lines") or ""
        metadata = (r.get("extra") or {}).get("metadata") or {}

        out.append({
            "tool": "code_scanning",
            "rule": r.get("check_id", ""),
            "severity": severity,
            "title": message,
            "file": path,
            "line": line,
            "snippet": snippet,
            "cwe": metadata.get("cwe") or [],
            "owasp": metadata.get("owasp") or [],
            "fingerprint": _fingerprint(r.get("check_id", ""), path, line, snippet),
        })
    return out


def _normalize_path(path: str, repo_root: str) -> str:
    if not path.startswith("/"):
        return path
    abs_root = os.path.abspath(repo_root).rstrip("/")
    abs_file = os.path.abspath(path)
    if abs_root and abs_file.startswith(abs_root + "/"):
        return abs_file[len(abs_root) + 1:]
    return path.lstrip("/")


def _fingerprint(rule: str, path: str, line: int, snippet: str) -> str:
    parts = f"{rule}|{path}|{line}|{snippet[:80]}"
    return hashlib.sha256(parts.encode()).hexdigest()[:16]

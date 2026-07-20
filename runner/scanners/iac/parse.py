"""Parse Checkov JSON output into normalized Finding dicts."""
from __future__ import annotations

import hashlib
import os

from runner.scanners._context import read_code_window

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}


def _normalize_path(file_path: str, repo_root: str) -> str:
    abs_root = os.path.abspath(repo_root).rstrip("/")
    abs_file = os.path.abspath(file_path)
    if abs_file.startswith(abs_root + "/"):
        return abs_file[len(abs_root) + 1 :]
    return file_path.lstrip("/")


def _fingerprint(chk: dict) -> str:
    parts = (
        chk.get("check_id", ""),
        chk.get("file_path", ""),
        chk.get("resource", ""),
    )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def parse_checkov_results(raw: dict | list, *, repo_root: str) -> list[dict]:
    # checkov -o json emits a single object for one framework, but a JSON array
    # of objects (one per framework) when multiple frameworks run. Merge every
    # entry's failed_checks so the multi-framework case doesn't crash on .get.
    entries = raw if isinstance(raw, list) else [raw]
    failed: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        res = entry.get("results") or {}
        if isinstance(res, dict):
            failed.extend(res.get("failed_checks") or [])
    out: list[dict] = []
    for chk in failed:
        sev = _SEVERITY_MAP.get((chk.get("severity") or "").upper(), "medium")
        line_range = chk.get("file_line_range") or [1, 1]
        line = int(line_range[0]) if line_range else 1
        rel_file = _normalize_path(chk.get("file_path", ""), repo_root)
        finding = {
            "tool": "iac_scanning",
            "check_id": chk.get("check_id", ""),
            "title": chk.get("check_name", ""),
            "severity": sev,
            "file": rel_file,
            "line": line,
            "resource": chk.get("resource", ""),
            "guideline": chk.get("guideline", ""),
            "fingerprint": _fingerprint(chk),
        }
        # Checkov does not emit a code window; the runner reads it from source.
        # File-level checks report line 0 (no specific line) — anchor their
        # window at the file head so the analyst still sees the config.
        window_line = line if line >= 1 else 1
        window, window_start = read_code_window(repo_root, rel_file, window_line)
        if window is not None:
            finding["code_window"] = window
            finding["code_window_start_line"] = window_start
        out.append(finding)
    return out

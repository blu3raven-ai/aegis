"""Parse Checkov JSON output into normalized Finding dicts."""
from __future__ import annotations

import hashlib
import os

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


def parse_checkov_results(raw: dict, *, repo_root: str) -> list[dict]:
    results = raw.get("results") or {}
    failed = results.get("failed_checks") or []
    out: list[dict] = []
    for chk in failed:
        sev = _SEVERITY_MAP.get((chk.get("severity") or "").upper(), "medium")
        line_range = chk.get("file_line_range") or [1, 1]
        line = int(line_range[0]) if line_range else 1
        out.append(
            {
                "tool": "iac_scanning",
                "check_id": chk.get("check_id", ""),
                "title": chk.get("check_name", ""),
                "severity": sev,
                "file": _normalize_path(chk.get("file_path", ""), repo_root),
                "line": line,
                "resource": chk.get("resource", ""),
                "guideline": chk.get("guideline", ""),
                "fingerprint": _fingerprint(chk),
            }
        )
    return out

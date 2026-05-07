#!/usr/bin/env python3
"""Enrich BetterLeaks findings with surrounding source context.

Usage:
  python3 enrich_context.py <findings.json> <repo_dir> [context_lines]

Reads betterleaks_raw.json, adds ContextBefore and ContextAfter (default 3
lines each) by running `git show <commit>:<file>` against the cloned repo.
Must be called while the repo clone is still on disk.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from pathlib import Path


CONTEXT_LINES = 3

# Valid git ref: 7-64 hex characters (short SHA through full SHA-256)
_VALID_GIT_REF = re.compile(r"^[0-9a-fA-F]{7,64}$")


def _validate_git_ref(commit: str) -> bool:
    """Validate that a commit hash contains only hex chars (7-64 length)."""
    return bool(_VALID_GIT_REF.match(commit))


def _validate_file_path(file_path: str) -> bool:
    """Validate that a file path doesn't attempt directory traversal."""
    if ".." in file_path:
        return False
    if file_path.startswith("/"):
        return False
    return True


def _get_file_at_commit(repo_dir: str, commit: str, file_path: str) -> list[str] | None:
    """Return file lines at a specific commit via git show."""
    if not _validate_git_ref(commit):
        logging.getLogger(__name__).warning(
            "[!] Blocked invalid commit ref: %r", commit
        )
        return None
    if not _validate_file_path(file_path):
        logging.getLogger(__name__).warning(
            "[!] Blocked invalid file path: %r", file_path
        )
        return None
    try:
        result = subprocess.run(
            ["git", "show", f"{commit}:{file_path}"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        return result.stdout.splitlines()
    except Exception:
        return None


def _get_file_current(repo_dir: str, file_path: str) -> list[str] | None:
    """Fallback: read file directly from working tree."""
    try:
        full = Path(repo_dir) / file_path
        if full.exists():
            return full.read_text(errors="replace").splitlines()
        return None
    except Exception:
        return None


def enrich(findings: list[dict], repo_dir: str, context_lines: int = CONTEXT_LINES) -> list[dict]:
    for finding in findings:
        file_path = finding.get("File") or finding.get("file") or ""
        raw_line = finding.get("Line") or finding.get("line")
        commit = finding.get("Commit") or finding.get("commit") or ""

        if not file_path or not raw_line:
            continue

        try:
            line_num = int(raw_line)
        except (ValueError, TypeError):
            continue

        lines = None
        if commit:
            lines = _get_file_at_commit(repo_dir, commit, file_path)
        if lines is None:
            lines = _get_file_current(repo_dir, file_path)
        if lines is None:
            continue

        # line_num is 1-indexed
        idx = line_num - 1
        before_start = max(0, idx - context_lines)
        after_end = min(len(lines), idx + context_lines + 1)

        finding["ContextBefore"] = lines[before_start:idx]
        finding["ContextAfter"] = lines[idx + 1 : after_end]

    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    _logger = logging.getLogger(__name__)

    if len(sys.argv) < 3:
        _logger.error("[!] Usage: enrich_context.py <findings.json> <repo_dir> [context_lines]")
        sys.exit(1)

    findings_path = sys.argv[1]
    repo_dir = sys.argv[2]
    ctx = int(sys.argv[3]) if len(sys.argv) > 3 else CONTEXT_LINES

    with open(findings_path, encoding="utf-8") as f:
        findings = json.load(f)

    if not findings:
        sys.exit(0)

    enriched = enrich(findings, repo_dir, ctx)

    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(enriched, f, ensure_ascii=False)

    _logger.info("[+] Context enriched %d finding(s)", len(enriched))

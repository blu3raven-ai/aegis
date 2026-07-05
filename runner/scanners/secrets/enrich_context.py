"""Enrich BetterLeaks findings with surrounding source context.

Adds ``ContextBefore`` / ``ContextAfter`` (3 lines either side by default) to
each finding by reading the file at the recorded commit via ``git show``, or
falling back to the working tree. Must run while the repo clone is still on
disk.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from runner.scanners._subprocess import run_tool

logger = logging.getLogger(__name__)


CONTEXT_LINES = 3

# Valid git ref: 7-64 hex characters (short SHA through full SHA-256)
_VALID_GIT_REF = re.compile(r"^[0-9a-fA-F]{7,64}$")

_GIT_SHOW_TIMEOUT_S = 10.0


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


def _get_file_at_commit(
    repo_dir: str | Path, commit: str, file_path: str
) -> list[str] | None:
    """Return file lines at a specific commit via ``git show``."""
    if not _validate_git_ref(commit):
        logger.warning("[!] Blocked invalid commit ref: %r", commit)
        return None
    if not _validate_file_path(file_path):
        logger.warning("[!] Blocked invalid file path: %r", file_path)
        return None
    rc, stdout, _ = run_tool(
        ["git", "show", f"{commit}:{file_path}"],
        cwd=repo_dir,
        timeout=_GIT_SHOW_TIMEOUT_S,
    )
    if rc != 0:
        return None
    return stdout.splitlines()


def _get_file_current(repo_dir: str | Path, file_path: str) -> list[str] | None:
    """Fallback: read file directly from the working tree."""
    try:
        full = Path(repo_dir) / file_path
        if full.exists():
            return full.read_text(errors="replace").splitlines()
        return None
    except OSError:
        return None


def enrich(
    findings: list[dict[str, Any]],
    repo_dir: str | Path,
    context_lines: int = CONTEXT_LINES,
) -> list[dict[str, Any]]:
    """Annotate ``findings`` in place with ``ContextBefore`` / ``ContextAfter``.

    Findings without resolvable file/line are left untouched. Returns the same
    list for caller convenience.
    """
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

        idx = line_num - 1
        before_start = max(0, idx - context_lines)
        after_end = min(len(lines), idx + context_lines + 1)

        finding["ContextBefore"] = lines[before_start:idx]
        finding["ContextAfter"] = lines[idx + 1 : after_end]

    return findings


def enrich_file(
    findings_path: str | Path,
    repo_dir: str | Path,
    context_lines: int = CONTEXT_LINES,
) -> int:
    """Load ``findings_path``, enrich, write back in place. Returns count."""
    findings_path = Path(findings_path)

    with open(findings_path, encoding="utf-8") as f:
        findings = json.load(f)

    if not findings:
        return 0

    enriched = enrich(findings, repo_dir, context_lines)

    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(enriched, f, ensure_ascii=False)

    logger.info("[+] Context enriched %d finding(s)", len(enriched))
    return len(enriched)

"""Git-based file diff detector for SAST incremental scanning.

Phase 2c: computes which files changed between two commits so the
baseline+delta engine can skip unchanged files.

Cross-file taint analysis is deferred to v1.1 — this module only surfaces
directly changed files.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileDiff:
    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)


def compute_file_diff(
    checkout_path: Path,
    baseline_sha: str | None,
    head_sha: str,
) -> FileDiff:
    """Return the set of files that changed between baseline_sha and head_sha.

    When baseline_sha is None (first scan or no prior baseline), all tracked
    files at head_sha are returned as 'added' — the caller interprets this as
    a signal to perform a full scan rather than a delta scan.

    Rename (R) entries are treated as delete+add so the cache invalidates the
    old path and fresh findings are produced for the new path.
    """
    if baseline_sha is None:
        return _all_files_as_added(checkout_path, head_sha)

    result = subprocess.run(
        ["git", "diff", "--name-status", f"{baseline_sha}..{head_sha}"],
        cwd=checkout_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return _parse_name_status(result.stdout)


def _all_files_as_added(checkout_path: Path, head_sha: str) -> FileDiff:
    """Return every file in the tree at head_sha as 'added'."""
    result = subprocess.run(
        ["git", "ls-tree", "--name-only", "-r", head_sha],
        cwd=checkout_path,
        capture_output=True,
        text=True,
        check=True,
    )
    files = [line for line in result.stdout.splitlines() if line.strip()]
    return FileDiff(added=files)


def _parse_name_status(output: str) -> FileDiff:
    """Parse the output of 'git diff --name-status'."""
    added: list[str] = []
    modified: list[str] = []
    deleted: list[str] = []

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]

        if status == "A":
            added.append(parts[1])
        elif status == "M":
            modified.append(parts[1])
        elif status == "D":
            deleted.append(parts[1])
        elif status.startswith("R"):
            # R<similarity_score>\t<old_path>\t<new_path>
            if len(parts) >= 3:
                deleted.append(parts[1])
                added.append(parts[2])

    return FileDiff(added=added, modified=modified, deleted=deleted)

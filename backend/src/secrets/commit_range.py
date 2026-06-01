"""Enumerate commits in a baseline..head range for the secrets delta engine.

Phase 2d: secrets scanners must check NEW COMMITS, not just file diffs —
a secret introduced in any commit is still leaked even if later deleted.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class FullScanRequired(Exception):
    """Raised when baseline_sha is None — caller must trigger full history scan."""


@dataclass
class CommitInfo:
    sha: str
    author_email: str
    timestamp: datetime
    message: str
    changed_files: list[str] = field(default_factory=list)


# Separator unlikely to appear in commit messages
_SEP = "\x1f"
_RECORD_SEP = "\x1e"

_LOG_FORMAT = f"%H{_SEP}%ae{_SEP}%aI{_SEP}%s"


def enumerate_new_commits(
    checkout_path: Path,
    baseline_sha: str | None,
    head_sha: str,
) -> list[CommitInfo]:
    """Return commits in baseline_sha..head_sha order (oldest first).

    If baseline_sha is None, raises FullScanRequired — the caller should
    trigger periodic_sweep.enqueue_full_history_scan instead of delta scanning.

    Changed files per commit are retrieved via git show --name-only so the
    caller can use them for targeted scanning without re-running git log.
    Rename entries (R → old then new path) are both included.
    """
    if baseline_sha is None:
        raise FullScanRequired(
            "baseline_sha is None — full history scan required for this repo"
        )

    log_result = subprocess.run(
        [
            "git", "log",
            f"{baseline_sha}..{head_sha}",
            f"--format={_LOG_FORMAT}{_RECORD_SEP}",
            "--reverse",
        ],
        cwd=checkout_path,
        capture_output=True,
        text=True,
        check=True,
    )

    commits: list[CommitInfo] = []
    for record in log_result.stdout.split(_RECORD_SEP):
        record = record.strip()
        if not record:
            continue
        parts = record.split(_SEP, 3)
        if len(parts) < 4:
            continue
        sha, author_email, ts_str, message = parts
        timestamp = datetime.fromisoformat(ts_str).astimezone(timezone.utc)
        changed = _files_for_commit(checkout_path, sha)
        commits.append(
            CommitInfo(
                sha=sha.strip(),
                author_email=author_email.strip(),
                timestamp=timestamp,
                message=message.strip(),
                changed_files=changed,
            )
        )

    return commits


def _files_for_commit(checkout_path: Path, sha: str) -> list[str]:
    """Return the set of file paths touched by a single commit.

    --diff-filter=ACDMR excludes untracked/ignored paths; renames yield both
    the old and new path so scanners can associate secrets with the current name.
    """
    result = subprocess.run(
        [
            "git", "show",
            "--name-status",
            "--diff-filter=ACDMR",
            "--format=",          # suppress the commit header
            sha,
        ],
        cwd=checkout_path,
        capture_output=True,
        text=True,
        check=True,
    )
    files: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R") and len(parts) >= 3:
            # Rename: include both old name and new name
            files.append(parts[1])
            files.append(parts[2])
        elif len(parts) >= 2:
            files.append(parts[1])
    return files

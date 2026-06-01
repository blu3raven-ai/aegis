"""Commit attribution helper for finding ingest (spec §5.6).

Uses `git blame -p` (porcelain) to find which commit last touched the line
where a finding was detected. Called during ingest; any failure leaves the
attribution fields NULL so the scan proceeds normally.

PR URL is derived from the commit message only (no live API calls). If the
merge commit follows the standard GitHub merge-commit format the PR number
is extracted and turned into a URL using the remote origin URL. When the
remote is absent or the pattern does not match, pr_url stays None.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# GitHub merge-commit message patterns:
#   "Merge pull request #N from …"
#   "Merged pull request #N …"  (GitHub squash-merge)
_PR_NUMBER_RE = re.compile(r"[Mm]erged? pull request #(\d+)", re.IGNORECASE)
_GH_REMOTE_RE = re.compile(
    r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/\s.]+?)(?:\.git)?$"
)


@dataclass
class CommitAttribution:
    commit_sha: str
    author_email: str
    author_name: str
    authored_at: datetime
    pr_url: str | None = field(default=None)


def attribute_to_commit(
    checkout_path: Path,
    file_path: str,
    line: int,
) -> CommitAttribution | None:
    """Use git blame -p to find the commit that last touched a line.

    Returns None when git is unavailable, the file no longer exists in the
    checkout, or the blame output cannot be parsed.
    """
    try:
        result = subprocess.run(
            ["git", "blame", "-p", "-L", f"{line},{line}", "--", file_path],
            cwd=checkout_path,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.debug("git blame unavailable: %s", exc)
        return None

    if result.returncode != 0:
        logger.debug(
            "git blame exited %d for %s:%d — %s",
            result.returncode,
            file_path,
            line,
            result.stderr.strip(),
        )
        return None

    return _parse_porcelain(result.stdout, checkout_path)


def _parse_porcelain(output: str, checkout_path: Path) -> CommitAttribution | None:
    """Parse git blame --porcelain output into a CommitAttribution."""
    lines = output.splitlines()
    if not lines:
        return None

    # First line: "<sha> <orig_line> <final_line> [<num_lines>]"
    header = lines[0].split()
    if not header:
        return None
    sha = header[0]
    if len(sha) < 7:
        return None

    fields: dict[str, str] = {}
    for ln in lines[1:]:
        if ln.startswith("\t"):
            # Tab-prefixed line is the source line content — stop here
            break
        if " " in ln:
            key, _, value = ln.partition(" ")
            fields[key] = value

    author_name = fields.get("author", "")
    author_email = fields.get("author-mail", "").strip("<>")
    author_time_str = fields.get("author-time", "")
    author_tz_str = fields.get("author-tz", "+0000")

    if not author_time_str:
        return None

    try:
        authored_at = _parse_unix_with_tz(int(author_time_str), author_tz_str)
    except (ValueError, OverflowError):
        authored_at = datetime.now(timezone.utc)

    pr_url = _find_pr_url(sha, checkout_path)

    return CommitAttribution(
        commit_sha=sha,
        author_email=author_email,
        author_name=author_name,
        authored_at=authored_at,
        pr_url=pr_url,
    )


def _parse_unix_with_tz(unix_ts: int, tz_str: str) -> datetime:
    """Convert a UNIX timestamp and git tz string (e.g. +0530) to UTC datetime."""
    dt_utc = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return dt_utc


def _find_pr_url(sha: str, checkout_path: Path) -> str | None:
    """Return a GitHub PR URL if the commit message contains a merge commit pattern."""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%B", sha],
            cwd=checkout_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    commit_body = result.stdout
    pr_match = _PR_NUMBER_RE.search(commit_body)
    if not pr_match:
        return None
    pr_number = pr_match.group(1)

    remote_url = _get_remote_url(checkout_path)
    if not remote_url:
        return None

    gh_match = _GH_REMOTE_RE.search(remote_url)
    if not gh_match:
        return None

    owner = gh_match.group("owner")
    repo = gh_match.group("repo")
    return f"https://github.com/{owner}/{repo}/pull/{pr_number}"


def _get_remote_url(checkout_path: Path) -> str | None:
    """Return the origin remote URL, or None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=checkout_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None

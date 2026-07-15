"""Positive-only verification that an AI-authored fix diff actually applies.

``git apply --check`` is a pure dry-run — it never writes and never executes code,
so it is safe against untrusted repo contents. Returns True ONLY when the diff
applies cleanly to the checkout; a malformed/prose fix, a context mismatch, a
missing git binary, or a timeout all return False. An unverifiable fix is simply
left un-badged in the UI — never flagged as broken — so a strict check can't turn
a usable suggestion into a scary warning.
"""
from __future__ import annotations

import subprocess


def fix_applies(diff: str, repo_root: str) -> bool:
    """True iff ``diff`` (a unified diff) applies cleanly at ``repo_root``."""
    if not diff or not diff.strip():
        return False
    # A prose "fix" (1-3 sentences) isn't a patch — nothing to verify.
    if "@@" not in diff or "--- " not in diff:
        return False
    # git apply rejects a patch with no trailing newline ("corrupt patch"); the
    # stored fix is often .strip()ed, so restore it before checking.
    if not diff.endswith("\n"):
        diff += "\n"
    try:
        proc = subprocess.run(
            ["git", "apply", "--check", "-"],
            input=diff.encode("utf-8", "replace"),
            cwd=repo_root,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0

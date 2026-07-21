"""Find the runnable entry a coding agent would autonomously execute during setup.

Detonation needs *something to run*. This detects the highest-signal auto-run
triggers — the ones an agent (or ``npm install``) fires without a human deciding
to — and returns the command to detonate, or None to skip. It does NOT try to run
arbitrary code paths: only entries that are, by their own convention, executed as
part of setup. No match → skip (detonation is opt-in and never guesses).

Pure and table-tested; the caller feeds the returned command to ``detonate``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# npm lifecycle scripts that run automatically on `npm install` — the classic
# supply-chain execution point, and exactly the "agent runs setup" scenario.
_NPM_AUTO_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
# Conventionally-named setup scripts an agent is told to run.
_SETUP_SCRIPTS = ("setup.sh", "install.sh", "bootstrap.sh")
# Make targets an agent commonly runs to set up a repo.
_MAKE_TARGETS = ("install", "setup", "bootstrap")


@dataclass(frozen=True)
class DetonationEntry:
    """A runnable setup entry worth detonating."""

    cmd: tuple[str, ...]  # argv to run in the sandbox
    ecosystem: str        # "npm" | "shell" — hints the base image to build
    source: str           # where it was found, for the finding's evidence
    body: str = ""        # the raw script text (npm script value / setup-script
                          # contents), so triage can check it for obfuscation


def _npm_entry(repo_root: Path) -> DetonationEntry | None:
    pkg = repo_root / "package.json"
    if not pkg.is_file():
        return None
    try:
        scripts = json.loads(pkg.read_text(encoding="utf-8", errors="replace")).get("scripts") or {}
    except (ValueError, OSError):
        return None
    if not isinstance(scripts, dict):
        return None
    for name in _NPM_AUTO_SCRIPTS:
        if isinstance(scripts.get(name), str) and scripts[name].strip():
            return DetonationEntry(
                cmd=("npm", "run", name, "--silent"),
                ecosystem="npm",
                source=f"package.json:scripts.{name}",
                body=scripts[name],
            )
    return None


# Cap the script read — an obfuscation check needs the head, not a padded file.
_MAX_BODY_BYTES = 64 * 1024


def _script_entry(repo_root: Path) -> DetonationEntry | None:
    for name in _SETUP_SCRIPTS:
        p = repo_root / name
        if p.is_file():
            try:
                body = p.read_text(encoding="utf-8", errors="replace")[:_MAX_BODY_BYTES]
            except OSError:
                body = ""
            return DetonationEntry(cmd=("sh", name), ecosystem="shell", source=name, body=body)
    return None


def _pip_entry(repo_root: Path) -> DetonationEntry | None:
    # `pip install .` runs setup.py / a pyproject build backend: arbitrary code
    # at install time, the Python equivalent of an npm postinstall.
    for name in ("setup.py", "pyproject.toml"):
        p = repo_root / name
        if p.is_file():
            try:
                body = p.read_text(encoding="utf-8", errors="replace")[:_MAX_BODY_BYTES]
            except OSError:
                body = ""
            return DetonationEntry(
                cmd=("pip", "install", "--no-build-isolation", "."),
                ecosystem="python", source=name, body=body,
            )
    return None


def _make_entry(repo_root: Path) -> DetonationEntry | None:
    p = repo_root / "Makefile"
    if not p.is_file():
        return None
    try:
        body = p.read_text(encoding="utf-8", errors="replace")[:_MAX_BODY_BYTES]
    except OSError:
        return None
    for target in _MAKE_TARGETS:
        if re.search(rf"^{target}\s*:", body, re.MULTILINE):
            return DetonationEntry(
                cmd=("make", target), ecosystem="shell",
                source=f"Makefile:{target}", body=body,
            )
    return None


def detect_entry(repo_root: str) -> DetonationEntry | None:
    """The setup entry to detonate, or None. Checks the auto-run install points
    across ecosystems: npm lifecycle scripts, pip build (setup.py/pyproject),
    a Makefile setup target, then a conventional setup script."""
    root = Path(repo_root)
    if not root.is_dir():
        return None
    return (
        _npm_entry(root)
        or _pip_entry(root)
        or _make_entry(root)
        or _script_entry(root)
    )

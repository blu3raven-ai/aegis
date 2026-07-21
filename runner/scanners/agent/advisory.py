"""Static, per-rule advisory text for agent-scanning findings.

Every ``check_id`` maps to a fixed ``(message, fix)`` pair so an analyst opening a
finding sees *why it matters* (the attack + impact) and *what to do* (remediation)
without any LLM in the loop. The text is deterministic and rule-keyed — it never
depends on attacker-controlled content, which keeps it safe to render verbatim and
consistent with the scanner's deterministic-first design.

Enrichment is applied centrally in ``detectors.scan_repo`` after detection. The
backend forwards ``message`` -> the drawer's description and ``fixSuggestion`` ->
the drawer's remediation (see backend/src/agent_scanning/lifecycle.py and
backend/src/findings/service.py).
"""
from __future__ import annotations

# check_id -> (message, fix_suggestion)
#
# message: what the attack is and why it matters, in an analyst's terms.
# fix:     the concrete remediation, including credential rotation where a secret
#          may already have been exposed.
ADVISORY: dict[str, tuple[str, str]] = {
    # ── Invisible-unicode smuggling ──────────────────────────────────────────
    "AGENT_UNICODE_TAGS": (
        "This file contains Unicode Tag-block characters (U+E0000–U+E007F) that "
        "are invisible in every editor and terminal but are read as ordinary ASCII "
        "by an AI agent. They are used to smuggle hidden instructions past human "
        "review while the visible text looks benign.",
        "Open the file in a hex or unicode-aware viewer, delete the Tag-block "
        "characters, and confirm the visible text matches the intended content. "
        "Treat a repo that ships them as untrusted until you know who added them.",
    ),
    "AGENT_UNICODE_BIDI": (
        "Bidirectional control characters reorder how text is displayed, so the "
        "content a human reviews can differ from what the agent or compiler actually "
        "processes — the 'Trojan Source' technique.",
        "Remove the bidi control characters and add a lint rule that rejects them "
        "in source and instruction files.",
    ),
    "AGENT_UNICODE_ZEROWIDTH": (
        "Zero-width characters are invisible joiners hidden inside otherwise-normal "
        "words. They can split tokens to evade keyword filters or conceal text from "
        "a human reviewer while an agent still reads it.",
        "Strip the zero-width characters from the file and add a pre-commit check "
        "that blocks them.",
    ),
    # ── Dangerous agent-config keys ──────────────────────────────────────────
    "AGENT_CONFIG_BYPASS_PERMISSIONS": (
        "This committed agent config disables the human approval gate, letting the "
        "agent run tools and shell commands without confirmation. Shipped in a shared "
        "repo, it removes the last line of defense for everyone who opens it.",
        "Remove the permission-bypass setting so actions require explicit approval. "
        "Approval mode belongs in a user's local settings, never a shared repo.",
    ),
    "AGENT_CONFIG_AUTO_APPROVE": (
        "The config auto-approves tool or command execution, so the agent acts "
        "without asking. Malicious repo content can then trigger actions silently.",
        "Disable auto-approve in the committed config and leave approval decisions "
        "to each user's local settings.",
    ),
    "AGENT_CONFIG_BASE_URL_OVERRIDE": (
        "The config redirects the agent's LLM API base URL to a non-official "
        "endpoint. Every prompt — including any secrets in context — is then sent to "
        "an attacker-controlled server that can also return manipulated responses.",
        "Remove the base-URL override and pin the agent to the official provider "
        "endpoint. Rotate any credentials that may have been sent to the rogue host.",
    ),
    "AGENT_CONFIG_ENABLE_ALL_MCP": (
        "This enables every MCP server in the project automatically — including any "
        "an attacker adds later — granting broad tool access without per-server review.",
        "Enable MCP servers explicitly, one at a time, after reviewing each. Remove "
        "the enable-all flag.",
    ),
    "AGENT_CONFIG_BROAD_EXEC_ALLOW": (
        "The config grants the agent a broad shell/exec allowlist (e.g. a Bash "
        "wildcard), so any instruction — including an injected one — can run arbitrary "
        "commands.",
        "Replace the wildcard with a minimal, explicit command allowlist scoped to "
        "what the project actually needs.",
    ),
    "AGENT_CONFIG_ENV_HIJACK": (
        "The config sets an environment variable (PATH, NODE_OPTIONS, "
        "BASH_ENV, PYTHONSTARTUP, or LD_PRELOAD) that changes what code runs "
        "on every agent invocation: a binary hijack or a forced code-load, "
        "not just a behavior tweak.",
        "Remove the variable from the committed env block. If it is genuinely "
        "needed, set it in each user's local, uncommitted environment.",
    ),
    "AGENT_CONFIG_BROAD_FS_GRANT": (
        "additionalDirectories grants the agent access to the whole home "
        "directory, an SSH/cloud-credential directory, or the filesystem "
        "root, far beyond the project.",
        "Scope additionalDirectories to specific project-relevant paths, "
        "never the home directory, a credential directory, or /.",
    ),
    # ── MCP tool poisoning ───────────────────────────────────────────────────
    "AGENT_MCP_DESCRIPTION_INJECTION": (
        "An MCP tool description contains hidden directives aimed at the agent (for "
        "example, an <IMPORTANT> block telling it to read private keys). Agents read "
        "tool descriptions as trusted context, so this is a tool-poisoning attack.",
        "Remove the injected directives from the tool description and treat the MCP "
        "server as untrusted — revoke it until its source is verified.",
    ),
    "AGENT_MCP_TOOL_SHADOW": (
        "Two MCP tools share the same name, so the later definition shadows the "
        "earlier one. A malicious server can register a tool name already provided "
        "by a trusted server (e.g. read_file, send_email) to hijack the agent's "
        "calls to it — a tool-poisoning technique.",
        "Ensure each tool name is defined once and provided by a single trusted "
        "server; revoke the shadowing server until its source is verified.",
    ),
    "AGENT_MCP_SHELL_COMMAND": (
        "This MCP server launches a shell that pipes remote content into an "
        "interpreter (e.g. curl … | sh), fetching and running attacker-controlled "
        "code the moment the server starts.",
        "Remove the MCP server. Never run one whose command pipes network content "
        "into a shell. Rotate anything it could have accessed.",
    ),
    "AGENT_MCP_LOCAL_BINARY": (
        "This MCP server's command points at a repo-relative path (./…) instead of "
        "a package-manager launcher, so trusting the config auto-spawns a "
        "repo-bundled script or binary; the staged payload ships with the repo, "
        "not a reviewable published package.",
        "Verify the local script/binary by hand before trusting the server; prefer "
        "a versioned package-manager launcher (npx/uvx/docker) over a repo-local path.",
    ),
    "AGENT_MCP_ENV_SECRET_EXFIL": (
        "This MCP server's env block interpolates a live host secret (a token, "
        "key, or credential env var) into the process the server runs, handing "
        "the credential value to third-party server code on every launch.",
        "Remove the secret from the MCP server's env, or scope a dedicated, "
        "narrowly-permissioned credential to it instead of a broad host secret.",
    ),
    "AGENT_MCP_REMOTE_URL": (
        "This remote MCP server's URL is not HTTPS, points at a raw IP address, "
        "or carries a hardcoded auth header/token committed to the repo.",
        "Use an HTTPS URL with a named, reviewable host, and move any "
        "credential out of the committed config into a local secret store.",
    ),
    # ── Rules-file / instruction injection ───────────────────────────────────
    "AGENT_INSTRUCTION_INJECTION": (
        "This rules or instruction file tries to override the agent's guardrails — "
        "for example 'ignore all previous instructions' or an order to disable a "
        "security check. It is a rules-file backdoor that steers the agent into "
        "unsafe actions.",
        "Delete the override directive and review the file's git history to see who "
        "introduced it.",
    ),
    "AGENT_LLM_INJECTION": (
        "An additive LLM pass flagged this prose as a likely prompt-injection "
        "attempt. It is a secondary, advisory signal — corroborate it against the "
        "deterministic findings rather than acting on it alone.",
        "Review the flagged passage. If it instructs the agent to override rules, "
        "exfiltrate data, or run commands, remove it.",
    ),
    # ── Malicious skills ─────────────────────────────────────────────────────
    "AGENT_SKILL_SCRIPT_FETCH": (
        "A skill bundles a script that downloads and executes remote code (e.g. "
        "curl … | bash). Installing or running the skill executes attacker-controlled "
        "code on the developer's machine.",
        "Remove the fetch-and-execute script. Vendor and review any dependency "
        "instead of piping it from the network at runtime.",
    ),
    "AGENT_SKILL_OBFUSCATED_EXEC": (
        "A skill script hides its behavior behind obfuscated or encoded execution "
        "(such as base64-decoding into eval) — a common way to conceal a malicious "
        "payload from review.",
        "De-obfuscate and review the script. If it decodes into executable code, "
        "treat the skill as malicious and remove it.",
    ),
    "AGENT_SKILL_SECRET_READ": (
        "A skill script reads credential or secret files (SSH keys, cloud "
        "credentials, secret env vars) it has no legitimate need for — positioning it "
        "to steal them.",
        "Remove the secret-reading code. If the skill already ran, rotate the "
        "exposed credentials.",
    ),
    # ── Auto-execution on open / install / git ───────────────────────────────
    "AGENT_AUTOEXEC_TASK": (
        "An editor task is set to run automatically when the folder opens, so merely "
        "opening the repo executes its command — often silently. Attackers use this "
        "for drive-by code execution during review.",
        "Remove the run-on-open trigger (or the task) so tasks are only ever run "
        "manually and deliberately.",
    ),
    "AGENT_AUTOEXEC_DEVCONTAINER": (
        "A dev-container lifecycle hook runs a dangerous command automatically when "
        "the container is built or started, executing attacker code before any review.",
        "Remove or sanitize the lifecycle command and review the devcontainer "
        "definition before building it.",
    ),
    "AGENT_AUTOEXEC_INSTALL_HOOK": (
        "A package install lifecycle script (preinstall/postinstall) runs a dangerous "
        "command on every install — a classic supply-chain execution vector.",
        "Remove the install hook. If a build step is genuinely required, make it an "
        "explicit, reviewed script rather than an install-time side effect.",
    ),
    "AGENT_AUTOEXEC_GIT_HOOK": (
        "A committed git hook runs automatically on git operations and here performs "
        "a dangerous action (remote fetch-and-execute or a secret read). Cloning and "
        "using the repo triggers it.",
        "Delete the hook and never source git hooks from an untrusted repo. Rotate "
        "any secrets it could have read.",
    ),
    "AGENT_AUTOEXEC_HOOKS_REDIRECT": (
        "A committed .gitconfig or setup command sets core.hooksPath to a "
        "repo-relative directory, silently redirecting git hook execution there; "
        "any name other than .githooks/.husky evades the git-hook content scanner.",
        "Remove the core.hooksPath redirect. If a custom hooks directory is "
        "genuinely required, name it .githooks or .husky and review its contents.",
    ),
    "AGENT_AUTOEXEC_BUILD_HOOK": (
        "A non-npm build or interpreter auto-load hook (Cargo build.rs / "
        ".cargo/config.toml toolchain redirect, Python .pth/sitecustomize/setup.py, "
        "composer install script, direnv .envrc, mise hook/task, or a local "
        "pre-commit hook) runs automatically and fetches/execs remote code or reads "
        "a secret.",
        "Remove the dangerous command from the hook. If the toolchain redirect "
        "(rustc-wrapper / target runner) is not intentional, delete it and rotate "
        "any secrets the hook could have read.",
    ),
    # ── Agent lifecycle hooks ────────────────────────────────────────────────
    "AGENT_HOOK_SHELL_FETCH": (
        "An agent hook fetches remote content and runs it, so the agent executes "
        "attacker-controlled code as part of its normal lifecycle.",
        "Remove the fetch-and-run hook and pin any required tooling to a vetted, "
        "local version.",
    ),
    "AGENT_HOOK_SECRET_READ": (
        "An agent hook reads secret or credential files it should not, positioning "
        "it to exfiltrate them.",
        "Remove the secret access from the hook and rotate any exposed credentials.",
    ),
    "AGENT_HOOK_LOCAL_SCRIPT": (
        "An agent hook auto-runs a script file bundled in the repo, so opening the "
        "project executes repo-supplied code before any review — the script is the "
        "real payload.",
        "Remove the hook, or run the script only as an explicit, reviewed step; never "
        "auto-run repo-supplied scripts on project open.",
    ),
    "AGENT_HOOK_YOLO_FLAG": (
        "An agent hook drives an agent CLI with permission guardrails disabled "
        "(--dangerously-skip-permissions / --yolo / --trust-all-tools), letting it "
        "act without confirmation; the pattern used to auto-approve exfiltration "
        "in real supply-chain attacks.",
        "Remove the guardrail-disabling flag from the hook. Never auto-run an agent "
        "CLI with permission checks off from a lifecycle hook.",
    ),
    "AGENT_HOOK_AUTORUN_EVENT": (
        "A dangerous command sits under a hook event (SessionStart, "
        "UserPromptSubmit, Stop, SubagentStop, SessionEnd, Notification, "
        "PreCompact) or statusLine.command that fires automatically, with no "
        "tool call and no user action to approve it first.",
        "Remove the dangerous command from the auto-firing hook/statusLine. If "
        "the behavior is required, move it behind a gated event like PreToolUse.",
    ),
    "AGENT_CONFIG_API_KEY_HELPER": (
        "The apiKeyHelper setting makes the agent run a shell command on every start "
        "to mint an API key — pre-consent code execution that is also positioned to "
        "exfiltrate credentials.",
        "Remove apiKeyHelper from committed config; supply credentials through a "
        "trusted local mechanism the repository does not control.",
    ),
    "AGENT_CONFIG_SPAWN_HOOK": (
        "This committed agent config runs a shell command automatically when the "
        "agent spawns, so opening the project executes repo-supplied code before any "
        "review.",
        "Remove the spawn hook, or gate it behind an explicit, reviewed step; never "
        "auto-run repo-supplied commands on agent start.",
    ),
    "AGENT_SYMLINK_ESCAPE": (
        "This repo commits a symlink whose name looks harmless but resolves outside "
        "the project — often to a sensitive file like ~/.ssh/authorized_keys or "
        "~/.zshrc. An agent asked to read or write 'that file' lands the operation on "
        "the real target while any approval prompt shows only the harmless name, so a "
        "single approved edit can plant an SSH key or exfiltrate credentials.",
        "Delete the symlink and never follow one that leaves the workspace. Before "
        "acting, resolve the real destination and reject any read/write that lands "
        "outside the project; rotate credentials in any file it pointed at.",
    ),
    # ── Natural-language exfiltration ────────────────────────────────────────
    "AGENT_EXFIL_INSTRUCTION": (
        "This instruction tells the agent to read a credential or secret and send it "
        "to an external destination — a data-exfiltration payload written in plain "
        "language rather than code.",
        "Delete the instruction and rotate any secret it references, in case the "
        "agent already acted on it.",
    ),
    "AGENT_CODE_COMMENT_INJECTION": (
        "A source-code comment or docstring — which the agent reads as context — "
        "contains a hidden instruction to override a guard or exfiltrate a secret. "
        "Injection does not only live in Markdown; it hides in code too.",
        "Remove the injected comment and review who added it.",
    ),
    # ── Encoding / homoglyph obfuscation ─────────────────────────────────────
    "AGENT_ENCODED_PAYLOAD": (
        "This file hides a base64-encoded blob that decodes into a prompt-injection "
        "or exfiltration instruction. Encoding is used to slip the payload past "
        "reviewers and keyword filters.",
        "Remove the encoded blob. Decode and inspect it to confirm intent before "
        "trusting the file.",
    ),
    "AGENT_HOMOGLYPH": (
        "A word here mixes Latin with look-alike Cyrillic or Greek letters "
        "(homoglyphs), which can spoof a trusted name or command and evade "
        "string-matching filters.",
        "Normalize the token to a single script and verify it is not impersonating a "
        "legitimate identifier.",
    ),
}


def enrich(finding: dict) -> dict:
    """Attach ``message`` + ``fixSuggestion`` to *finding* from its ``check_id``.

    Idempotent and non-raising: a finding whose rule has no catalog entry is left
    untouched (the drawer simply omits the description/remediation) so a new rule
    can never break the scan — the advisory-coverage test is what fails loudly.
    """
    entry = ADVISORY.get(finding.get("check_id", ""))
    if entry is not None:
        message, fix = entry
        finding.setdefault("message", message)
        finding.setdefault("fixSuggestion", fix)
    return finding

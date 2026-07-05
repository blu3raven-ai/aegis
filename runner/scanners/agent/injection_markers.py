"""Detect embedded-instruction markers in agent-loaded content.

Two high-signal, deterministic marker classes — not fuzzy natural-language
classification (that is left to the later LLM-judge pass), only the structural
tells an attacker uses to smuggle instructions past a human reviewer:

* **Concealment directives** — "do not mention this to the user", "keep this
  secret". Legitimate documentation never tells the agent to hide its actions.
* **Override directives** — "ignore all previous instructions", "disregard the
  above rules". The classic prompt-injection opener.
* **Pseudo-instruction tags** — ``<IMPORTANT>`` / ``<system>`` blocks embedded in
  an MCP tool description, the signature of MCP "tool poisoning".

Applied to MCP server/tool text nodes (tool poisoning) and to prose rules files
(the rules-file-backdoor concealment technique). Findings aggregate to one per
(file, rule) with a redacted sample.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

_MCP_INJECTION = "AGENT_MCP_DESCRIPTION_INJECTION"
_PROSE_INJECTION = "AGENT_INSTRUCTION_INJECTION"

_GUIDELINE = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)

# Tells the agent to conceal an action *from the user*. Requiring the
# concealment target (the user / them / anyone) avoids firing on ordinary
# English like "never notify the actor" or "never reveal existence to a viewer".
_CONCEAL = re.compile(
    r"\b(?:do\s*not|don't|never)\b[^.\n]{0,40}"
    r"\b(?:mention|tell\w*|reveal|disclos\w*|inform|notif\w*|report|acknowledge|warn|alert|let)\b"
    r"[^.\n]{0,40}\b(?:the\s+|any\s+)?(?:user|users|human|developer|reviewer|operator|maintainer|owner|them|anyone|nobody)\b"
    r"|\bwithout\b[^.\n]{0,30}\b(?:the\s+)?(?:user|human|anyone|them)\b[^.\n]{0,25}\b(?:know\w*|notic\w*|see\w*|aware|find\w*\s+out)\b"
    r"|\bkeep\s+(?:this|it)\b[^.\n]{0,25}\b(?:secret|hidden|confidential|between\s+us|to\s+yourself)\b",
    re.I,
)

# Tells the agent to discard its real instructions. The qualifier must be
# directional/possessive (previous, above, all, your, system, …) — a bare "the"
# is dropped so "override the confirm-prompt copy" no longer matches.
_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,30}"
    r"\b(?:previous|prior|above|preceding|earlier|all|these|following|your|my|system)\b[^.\n]{0,25}"
    r"\b(?:instruction|prompt|rule|direction|context|message|system)s?\b",
    re.I,
)

# Pseudo-instruction tags used to frame smuggled directives as authoritative.
_TAG = re.compile(
    r"<\s*/?\s*(?:important|system|secret|admin|instructions?|confidential|internal)\s*>",
    re.I,
)

_CROSS_FILE = (("conceal", _CONCEAL), ("override", _OVERRIDE))


def _fingerprint(rel_path: str, rule_id: str) -> str:
    return hashlib.sha1(f"agent:{rel_path}:{rule_id}".encode()).hexdigest()[:16]


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _redact(s: str) -> str:
    s = " ".join(s.split())
    return s[:120]


def _aggregate(rel_path: str, rule_id: str, severity: str, title: str,
               matches: list[tuple[int, str]]) -> dict:
    first_line = min(m[0] for m in matches)
    return {
        "check_id": rule_id,
        "title": title,
        "severity": severity,
        "file": rel_path,
        "line": first_line,
        "resource": rule_id,
        "guideline": _GUIDELINE,
        "fingerprint": _fingerprint(rel_path, rule_id),
        "evidence": {
            "count": len(matches),
            "firstLine": first_line,
            "sample": _redact(matches[0][1]),
        },
    }


def _find_in_text(text: str, patterns) -> list[tuple[int, str]]:
    """Return (line, matched-context) for each pattern hit in ``text``."""
    hits: list[tuple[int, str]] = []
    for _label, pat in patterns:
        for m in pat.finditer(text):
            hits.append((_line_of(text, m.start()), m.group(0)))
    return hits


def _walk_strings(node: Any):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_strings(v)


def scan_mcp(rel_path: str, text: str) -> list[dict]:
    """Flag injected instructions in any string node of an MCP config."""
    from runner.scanners.agent.config_keys import _load
    data = _load(text)
    if not isinstance(data, (dict, list)):
        return []
    matches: list[tuple[int, str]] = []
    for s in _walk_strings(data):
        for m in _TAG.finditer(s):
            matches.append((_line_of(text, text.find(s)), m.group(0)))
        for _label, pat in _CROSS_FILE:
            for m in pat.finditer(s):
                matches.append((_line_of(text, text.find(s)), m.group(0)))
    if not matches:
        return []
    return [_aggregate(
        rel_path, _MCP_INJECTION, "high",
        f"MCP config contains embedded agent instructions (tool poisoning) in {rel_path}",
        matches,
    )]


def scan_prose(rel_path: str, text: str) -> list[dict]:
    """Flag concealment/override directives in a prose rules file."""
    matches = _find_in_text(text, _CROSS_FILE)
    if not matches:
        return []
    return [_aggregate(
        rel_path, _PROSE_INJECTION, "high",
        f"Agent rules file contains concealment/override instructions in {rel_path}",
        matches,
    )]


_PROSE_BASENAMES = frozenset({
    "CLAUDE.md", "AGENTS.md", "GEMINI.md", "copilot-instructions.md", "SKILL.md",
    ".cursorrules", ".clinerules", ".windsurfrules",
})


def scan_injection(rel_path: str, text: str) -> list[dict]:
    """Dispatch a file to the marker detector appropriate for its type."""
    base = rel_path.rsplit("/", 1)[-1]
    if base == ".mcp.json" or rel_path == ".vscode/mcp.json":
        return scan_mcp(rel_path, text)
    if base in _PROSE_BASENAMES or base.endswith(".md") or base.endswith(".mdc"):
        return scan_prose(rel_path, text)
    return []

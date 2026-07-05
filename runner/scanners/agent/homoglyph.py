"""Detect homoglyph / confusable-character attacks in agent-instruction files.

A word that mixes scripts within a single token — a Latin word with a Cyrillic
or Greek look-alike swapped in (``pаypal``: the ``а`` is U+0430 Cyrillic) — reads
identically to a human but is a different string to a model, and is a classic way
to disguise a keyword or slip a directive past a reviewer. This is distinct from
the invisible-unicode detector (those characters have no glyph; these do).

Only **intra-token** script mixing is flagged. Legitimate multilingual docs put
different scripts in different words; a single token containing both a Latin
letter and a Cyrillic/Greek letter is almost always a confusable attack, so the
false-positive rate is very low.
"""
from __future__ import annotations

import hashlib
import re

_HOMOGLYPH = "AGENT_HOMOGLYPH"
_GUIDELINE = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)

# Contiguous runs of letters (any script) — the "tokens" we check for mixing.
_TOKEN = re.compile(r"[^\W\d_]{2,}", re.UNICODE)

_PROSE_BASENAMES = frozenset({
    "CLAUDE.md", "AGENTS.md", "GEMINI.md", "copilot-instructions.md", "SKILL.md",
    ".cursorrules", ".clinerules", ".windsurfrules",
})


def _is_target(rel_path: str) -> bool:
    base = rel_path.rsplit("/", 1)[-1]
    return base in _PROSE_BASENAMES or base.endswith((".md", ".mdc"))


def _is_latin(cp: int) -> bool:
    return (0x41 <= cp <= 0x5A) or (0x61 <= cp <= 0x7A) or (0x00C0 <= cp <= 0x024F)


def _is_cyrillic(cp: int) -> bool:
    return 0x0400 <= cp <= 0x04FF


def _is_greek(cp: int) -> bool:
    return 0x0370 <= cp <= 0x03FF


def _mixed_token(token: str) -> bool:
    """True if the token mixes Latin with Cyrillic or Greek letters."""
    has_latin = any(_is_latin(ord(c)) for c in token)
    if not has_latin:
        return False
    return any(_is_cyrillic(ord(c)) or _is_greek(ord(c)) for c in token)


def scan_homoglyphs(rel_path: str, text: str) -> list[dict]:
    if not _is_target(rel_path):
        return []
    for m in _TOKEN.finditer(text):
        token = m.group(0)
        if not _mixed_token(token):
            continue
        line = text.count("\n", 0, m.start()) + 1
        confusables = ", ".join(
            f"U+{ord(c):04X}" for c in token if _is_cyrillic(ord(c)) or _is_greek(ord(c))
        )
        fp = hashlib.sha1(f"agent:{rel_path}:{_HOMOGLYPH}".encode()).hexdigest()[:16]
        return [{
            "check_id": _HOMOGLYPH,
            "title": f"Mixed-script (homoglyph) characters in {rel_path}",
            "severity": "high",
            "file": rel_path,
            "line": line,
            "resource": _HOMOGLYPH,
            "guideline": _GUIDELINE,
            "fingerprint": fp,
            "evidence": {"token": token[:60], "confusables": confusables[:80]},
        }]
    return []

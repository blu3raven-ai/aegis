"""Detect invisible-unicode instruction smuggling in agent-loaded files.

Characters that are invisible to a human reviewer but still tokenized by a model
can hide instructions inside an otherwise-innocent rules file, skill, or config.
Three families are flagged, highest-signal first:

* **Tags block** (U+E0000–U+E007F) — an invisible mirror of ASCII. It has no
  legitimate use in a source repo, so any occurrence is treated as critical.
* **Bidirectional overrides** (the Trojan Source set) — reorder how text renders
  versus how it is parsed/tokenized.
* **Zero-width** characters — join/space/no-break codepoints with no visible
  glyph. Legitimate in some RTL/emoji prose, but anomalous in an English agent
  rules or JSON config file, so they are flagged only within the instruction
  surface (see targets.py), not repo-wide.

Findings are aggregated to one per (file, family): a rules file with fifty
hidden characters is one problem to triage, not fifty. Identity is stable
(file + rule id) so re-scans keep the finding's triage state.
"""
from __future__ import annotations

import hashlib

# U+E0000–U+E007F. Invisible ASCII smuggling — never legitimate in a repo.
_TAGS_LO, _TAGS_HI = 0xE0000, 0xE007F

# Trojan Source: embeddings, overrides, isolates, and the Arabic letter mark.
# Plain LRM/RLM (U+200E/200F) are deliberately excluded — they appear in
# legitimate bidirectional text and would drive false positives.
_BIDI_CONTROLS = frozenset({
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # LRE RLE PDF LRO RLO
    0x2066, 0x2067, 0x2068, 0x2069,          # LRI RLI FSI PDI
    0x061C,                                   # ALM
})

# Zero-width / invisible spacing. BOM (U+FEFF) is handled separately: legitimate
# as a leading byte-order mark, suspicious mid-file.
_ZERO_WIDTH = frozenset({
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x2060,  # word joiner
    0x2061, 0x2062, 0x2063, 0x2064,  # invisible math operators
    0xFEFF,  # zero-width no-break space (BOM)
})

_TAGS = "AGENT_UNICODE_TAGS"
_BIDI = "AGENT_UNICODE_BIDI"
_ZERO = "AGENT_UNICODE_ZEROWIDTH"

_GUIDELINE = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)


def _family(cp: int, offset: int) -> str | None:
    """Return the rule id for a suspicious codepoint, or None if benign."""
    if _TAGS_LO <= cp <= _TAGS_HI:
        return _TAGS
    if cp in _BIDI_CONTROLS:
        return _BIDI
    if cp in _ZERO_WIDTH:
        # A single leading BOM is legitimate; a BOM anywhere else is not.
        if cp == 0xFEFF and offset == 0:
            return None
        return _ZERO
    return None


_META = {
    _TAGS: ("critical", "Invisible Unicode Tag characters (ASCII smuggling) in {path}"),
    _BIDI: ("high", "Bidirectional override characters (Trojan Source) in {path}"),
    _ZERO: ("high", "Zero-width characters hidden in agent instruction file {path}"),
}


def _fingerprint(rel_path: str, rule_id: str) -> str:
    return hashlib.sha1(f"agent:{rel_path}:{rule_id}".encode()).hexdigest()[:16]


def scan_text(rel_path: str, text: str) -> list[dict]:
    """Scan one file's text; return an aggregated finding per (file, family)."""
    # Per family: [first_line, count, {codepoints}]
    hits: dict[str, list] = {}
    line = 1
    for offset, ch in enumerate(text):
        if ch == "\n":
            line += 1
            continue
        rule_id = _family(ord(ch), offset)
        if rule_id is None:
            continue
        entry = hits.get(rule_id)
        if entry is None:
            hits[rule_id] = [line, 1, {ord(ch)}]
        else:
            entry[1] += 1
            entry[2].add(ord(ch))

    findings: list[dict] = []
    for rule_id, (first_line, count, codepoints) in hits.items():
        severity, title_tmpl = _META[rule_id]
        sample = ", ".join(f"U+{cp:04X}" for cp in sorted(codepoints)[:5])
        findings.append({
            "check_id": rule_id,
            "title": title_tmpl.format(path=rel_path),
            "severity": severity,
            "file": rel_path,
            "line": first_line,
            # Stable across re-scans (no volatile count/offset) so the finding
            # keeps its identity and triage state.
            "resource": rule_id,
            "guideline": _GUIDELINE,
            "fingerprint": _fingerprint(rel_path, rule_id),
            "evidence": {
                "count": count,
                "codepoints": sample,
                "firstLine": first_line,
            },
        })
    return findings

"""Detect injection/exfil payloads hidden behind base64 encoding.

A base64 blob in an agent-instruction file is a common way to slip a directive
past a text scanner (and past a human reviewer): the visible file looks inert,
but a coding agent that decodes and follows it — or a reviewer who base64-decodes
"just to check" — gets the hidden instruction. This decodes candidate blobs and
re-runs the marker/exfil detectors on the *decoded* text.

False positives stay low because a finding is only raised when the decoded
content is itself malicious. An ordinary base64 blob — an embedded image, a key,
a hash — decodes to binary or unrelated text, matches nothing, and is ignored.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

from runner.scanners.agent.exfil_instruction import find_exfil
from runner.scanners.agent.injection_markers import _CONCEAL, _OVERRIDE, _TAG

_ENCODED = "AGENT_ENCODED_PAYLOAD"
_GUIDELINE = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)

# A base64 run long enough to carry a sentence; short tokens (ids, hashes) are
# skipped. Standard and URL-safe alphabets.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{48,}={0,2}")

_MAX_BLOBS = 200
_MAX_DECODE_BYTES = 16_384

# Prose / instruction files this runs on (source-comment payloads are handled by
# the code_comments pass masking to comments first).
_PROSE_BASENAMES = frozenset({
    "CLAUDE.md", "AGENTS.md", "GEMINI.md", "copilot-instructions.md", "SKILL.md",
    ".cursorrules", ".clinerules", ".windsurfrules",
})


def _is_target(rel_path: str) -> bool:
    base = rel_path.rsplit("/", 1)[-1]
    return base in _PROSE_BASENAMES or base.endswith((".md", ".mdc"))


def _decode(blob: str) -> str | None:
    """Best-effort decode a base64 blob to printable text, else None."""
    s = blob.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)[:_MAX_DECODE_BYTES]
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Require mostly-printable text — reject decoded binary (images, keys).
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t ")
    if not text or printable / len(text) < 0.9:
        return None
    return text


def _malicious(decoded: str) -> str | None:
    """Return a short reason if decoded text is an injection/exfil payload."""
    if _TAG.search(decoded) or _CONCEAL.search(decoded) or _OVERRIDE.search(decoded):
        return "injection directives"
    if find_exfil(decoded) is not None:
        return "credential exfiltration"
    return None


def scan_encoded(rel_path: str, text: str) -> list[dict]:
    if not _is_target(rel_path):
        return []
    for i, m in enumerate(_B64_BLOB.finditer(text)):
        if i >= _MAX_BLOBS:
            break
        decoded = _decode(m.group(0))
        if decoded is None:
            continue
        reason = _malicious(decoded)
        if reason is None:
            continue
        line = text.count("\n", 0, m.start()) + 1
        fp = hashlib.sha1(f"agent:{rel_path}:{_ENCODED}".encode()).hexdigest()[:16]
        return [{
            "check_id": _ENCODED,
            "title": f"Base64-encoded {reason} hidden in {rel_path}",
            "severity": "critical",
            "file": rel_path,
            "line": line,
            "resource": _ENCODED,
            "guideline": _GUIDELINE,
            "fingerprint": fp,
            "evidence": {"reason": reason, "decoded": " ".join(decoded.split())[:160]},
        }]
    return []

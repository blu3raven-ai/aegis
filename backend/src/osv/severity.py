"""Derive an app severity word from an OSV advisory body.

OSV advisories express severity two ways:

- a human word under ``database_specific.severity`` (GHSA / npm advisories), or
- a CVSS *vector* string under ``severity[]`` (CVE-native, PyPI/PYSEC, and
  Linux-distro advisories, which almost never carry the ``database_specific``
  word).

Reading only the first form left every advisory that ships a CVSS vector — the
majority outside the npm ecosystem — stored as ``"unknown"``. This module reads
the word when present and otherwise parses the CVSS vector, computes its base
score, and maps it to a qualitative band.
"""
from __future__ import annotations

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

# OSV ``database_specific.severity`` words → the app's canonical severity words.
_WORD = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Prefer the newest CVSS revision when an advisory lists more than one.
_CVSS_VERSION_RANK = {"CVSS_V4": 3, "CVSS_V3": 2, "CVSS_V2": 1}


def _word_from_base_score(score: float) -> str | None:
    """Map a CVSS base score to a severity word using the CVSS v3 bands.

    The v3 qualitative bands are applied uniformly to every CVSS revision so a
    9.5 always reads as ``critical`` regardless of whether the vector was scored
    under v2 (which has no native "critical" band), v3, or v4. A 0.0 ("None"
    rating) has no matching app word and returns ``None``.
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return None


def base_score_from_vector(vector: str) -> float | None:
    """Parse a CVSS vector string into its numeric base score, or None."""
    v = (vector or "").strip()
    if not v:
        return None
    try:
        if v.startswith("CVSS:4"):
            return CVSS4(v).base_score
        if v.startswith("CVSS:3"):
            return CVSS3(v).base_score
        # CVSS v2 vectors carry no ``CVSS:`` prefix.
        return CVSS2(v).base_score
    except (CVSSError, KeyError, ValueError, TypeError):
        return None


def base_score_from_osv_body(body: dict) -> float | None:
    """Highest-revision CVSS base score from an OSV body's ``severity[]``, or None."""
    entries = [
        s for s in (body.get("severity") or [])
        if isinstance(s, dict) and s.get("score")
    ]
    entries.sort(
        key=lambda s: _CVSS_VERSION_RANK.get(str(s.get("type", "")).upper(), 0),
        reverse=True,
    )
    for sev in entries:
        score = base_score_from_vector(sev["score"])
        if score is not None:
            return score
    return None


def severity_word_from_osv_body(body: dict) -> str | None:
    """Best-effort app severity word from an OSV advisory body, or None.

    Returns one of ``critical`` / ``high`` / ``medium`` / ``low``, or ``None``
    when neither a recognized ``database_specific.severity`` word nor a parseable
    CVSS vector is present. Callers apply their own fallback (``"unknown"`` for
    the finding row; ``None`` for the nullable mirror column).
    """
    ds = body.get("database_specific") or {}
    word = ds.get("severity")
    if isinstance(word, str) and word.strip().upper() in _WORD:
        return _WORD[word.strip().upper()]
    score = base_score_from_osv_body(body)
    if score is not None:
        return _word_from_base_score(score)
    return None

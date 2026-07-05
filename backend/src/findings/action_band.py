"""SSVC-style categorical action band for the findings surface.

Replaces the displayed 0-100 risk_score with a transparent, rule-driven band
(Act / Attend / Track). The band is derived ONLY from ground-truth signals —
KEV (binary), reachability (categorical, when present), severity (ordinal).
EPSS is never an input: it is displayed as a chip, never baked into a decision.
The rule is intentionally simple so the UI's signal chips fully explain why a
finding landed in its band.

Keep this in sync with the SQL CASE in findings/service.py (parity-tested).
"""
from __future__ import annotations

ACT = "act"
ATTEND = "attend"
TRACK = "track"

_HIGH_OR_ABOVE = frozenset({"critical", "high"})
_ORDINAL = {ACT: 3, ATTEND: 2, TRACK: 1}


def action_band(
    severity: str | None,
    *,
    kev_listed: bool,
    reachability: str | None = None,
) -> str:
    """Return 'act' | 'attend' | 'track' (first match wins)."""
    high = (severity or "").lower() in _HIGH_OR_ABOVE
    if kev_listed and high:
        return ACT
    if kev_listed:
        return ATTEND
    if reachability == "reachable" and high:
        return ATTEND
    return TRACK


def band_ordinal(band: str) -> int:
    """Sort weight: Act > Attend > Track. Unknown bands sort lowest."""
    return _ORDINAL.get(band, 0)

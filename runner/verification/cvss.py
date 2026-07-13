"""Deterministic CVSS 3.1 base-score computation.

The verifier LLM classifies the eight base metrics (enum only); this module
turns a complete, valid metric map into the canonical vector string and the
numeric base score. No model ever emits a number, so the score is auditable and
reproducible: the same metrics always yield the same score.
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_ALLOWED = {
    "AV": set("NALP"), "AC": set("LH"), "PR": set("NLH"), "UI": set("NR"),
    "S": set("UC"), "C": set("NLH"), "I": set("NLH"), "A": set("NLH"),
}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: the smallest 1-decimal number >= value, computed with
    the spec's integer-arithmetic form to avoid float-rounding drift."""
    i = round(value * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def score(metrics: dict[str, str]) -> tuple[str, float] | None:
    """Return (vector, base_score) for a complete CVSS 3.1 base-metric map, or
    None if any metric is missing or invalid — fail closed to "no CVSS shown"
    rather than emit a wrong number."""
    if not isinstance(metrics, dict):
        return None
    m: dict[str, str] = {}
    for key in _ORDER:
        val = str(metrics.get(key, "")).strip().upper()
        if val not in _ALLOWED[key]:
            return None
        m[key] = val

    scope_changed = m["S"] == "C"
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]

    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = _roundup(min(impact + exploitability, 10))

    vector = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _ORDER)
    return vector, round(base, 1)


if __name__ == "__main__":  # tiny self-check mirroring the reference vectors
    assert score({"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                  "S": "U", "C": "H", "I": "H", "A": "H"})[1] == 9.8
    assert score({"AV": "L", "AC": "L", "PR": "N", "UI": "R",
                  "S": "U", "C": "H", "I": "H", "A": "H"})[1] == 7.8
    assert score({"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                  "S": "C", "C": "H", "I": "H", "A": "H"})[1] == 10.0
    assert score({"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                  "S": "U", "C": "N", "I": "N", "A": "N"})[1] == 0.0
    assert score({"AV": "X"}) is None
    print("cvss self-check ok")

"""Heuristic fallbacks for Argus connector methods.

These implement the local approximations that fire when:
  - ARGUS_ENDPOINT / ARGUS_API_KEY are not configured (Mode A)
  - The Argus remote is unreachable or returns an error (graceful degradation)

All formulas are intentionally simple and conservative. They are documented
so operators can reason about why a finding got a given score.

Fallback contract (spec §7.6):
  score_finding   → severity_map[severity] + epss_bonus
  decide_go_no_go → "warn" if any high+ finding; "allow" otherwise
  explain_chain   → templated string from chain type + finding count
  fetch_premium_rule_pack → empty dict; built-in rules unaffected
"""
from __future__ import annotations

# Base scores by severity. Critical is capped at 90 so Argus always has headroom
# to push a finding to 100 via its additional signal.
_SEVERITY_BASE: dict[str, float] = {
    "critical": 90.0,
    "high": 70.0,
    "medium": 45.0,
    "low": 20.0,
    "informational": 5.0,
    "info": 5.0,
}

# Severities considered high-or-above for go/no-go blocking decisions.
_HIGH_AND_ABOVE = {"critical", "high"}

# Bonus points added per unit of EPSS. EPSS is 0–1; a score of 1.0 adds
# 10 points. This nudges exploitable CVEs upward without dominating severity.
_EPSS_MULTIPLIER = 10.0


def heuristic_score(
    severity: str,
    epss: float = 0.0,
    reachability_bonus: float = 0.0,
    chain_bonus: float = 0.0,
) -> float:
    """Return a risk score in [0, 100] from local signals only.

    Args:
        severity: CVE/finding severity string.
        epss: EPSS exploitation probability [0, 1].
        reachability_bonus: Caller-supplied bonus for reachability evidence
            (e.g. +5 when a call chain reaches the vulnerable function).
        chain_bonus: Bonus for being part of an attack chain (e.g. +5 when
            two or more correlated findings point at the same service).
    """
    base = _SEVERITY_BASE.get((severity or "").lower(), 20.0)
    raw = base + (epss * _EPSS_MULTIPLIER) + reachability_bonus + chain_bonus
    return round(min(raw, 100.0), 2)


def heuristic_go_no_go(findings: list[dict]) -> dict:
    """Return a go/no-go decision dict from local severity signals.

    Decision logic:
      - "block" if any finding has severity=critical
      - "warn"  if any finding has severity=high
      - "allow" otherwise

    Returns a dict with keys: decision, blockers, rationale.
    """
    blockers: list[str] = []
    has_critical = False
    has_high = False

    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev == "critical":
            has_critical = True
            if f.get("id"):
                blockers.append(f["id"])
        elif sev in _HIGH_AND_ABOVE:
            has_high = True

    if has_critical:
        return {
            "decision": "block",
            "blockers": blockers,
            "rationale": "One or more critical-severity findings present (heuristic).",
        }
    if has_high:
        return {
            "decision": "warn",
            "blockers": [],
            "rationale": "One or more high-severity findings present (heuristic).",
        }
    return {
        "decision": "allow",
        "blockers": [],
        "rationale": "No high-severity findings detected (heuristic).",
    }


def heuristic_explain(chain: dict) -> str:
    """Return a templated markdown explanation for an attack chain.

    chain is expected to have:
      - chain_type (str)  — e.g. "cve_to_secret"
      - findings (list)   — finding metadata dicts
      - edges (list)      — edge dicts

    The explanation is intentionally terse; Argus produces the rich version.
    """
    chain_type = chain.get("chain_type", "unknown")
    finding_count = len(chain.get("findings", []))
    edge_count = len(chain.get("edges", []))

    return (
        f"**Attack chain ({chain_type})**\n\n"
        f"This chain contains **{finding_count}** finding(s) connected by "
        f"**{edge_count}** edge(s).\n\n"
        "Detailed remediation guidance is available when Argus is configured."
    )


def empty_rule_pack() -> dict:
    """Return an empty rule pack.

    Built-in rules are unaffected; this simply signals that no premium rules
    are available without Argus.
    """
    return {}

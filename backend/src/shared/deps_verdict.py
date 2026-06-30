"""Categorical, recall-safe verdict for dependency findings.

Fuses the runner's reachability label with KEV (resolved by the caller) into a
verdict. No aggregate number. `ruled_out` (hidden) fires ONLY when the vulnerable
code has no path AND the CWE class has a proven-low LLM miss rate AND it's not
KEV-listed. The runner only emits `no_path` when grounded; ungrounded → `unknown`.
"""
from __future__ import annotations

SUPPRESSIBLE_CWES: frozenset[str] = frozenset({
    "CWE-78", "CWE-79", "CWE-89", "CWE-90",  # OS/SQL/LDAP injection, XSS
    "CWE-918",                                  # SSRF
    "CWE-22",                                   # path traversal
})


def deps_verdict(reachability: str, *, kev_listed: bool, cwes: list[str] | None) -> str:
    """Return 'needs_verify' | 'possible' | 'ruled_out' for a deps finding."""
    if kev_listed:
        return "needs_verify"            # actively exploited — never hidden
    if reachability == "reachable":
        return "needs_verify"
    if reachability == "no_path":
        if any(c in SUPPRESSIBLE_CWES for c in (cwes or [])):
            return "ruled_out"
        return "possible"                # high-miss class: visible, de-emphasized
    return "needs_verify"                # 'unknown' / anything else → visible

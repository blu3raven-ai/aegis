"""Resolve a needs_runtime_verification finding from observed probe results.

Mechanical only. For the common broken-access shape the no-credential request's
status is decisive: a 2xx with no credential means a sensitive path served real
content unauthenticated (flaw confirmed); a 401/403 means the control is enforced
(ruled out). Anything else — redirects, 404s, 5xx, transport failures, no probe
response — is INCONCLUSIVE and leaves the verdict untouched. A wrong verdict is
worse than an unresolved one, so we only flip on an unambiguous signal.
"""
from __future__ import annotations

from dataclasses import dataclass

from runner.sandbox.probe_runner import ProbeResult

# ponytail: mechanical-only. An LLM "interpret these responses" fallback for the
# ambiguous bucket is the upgrade path if real cases need it — until then,
# ambiguous → skip is always safe (never a false verdict).

_UNRESOLVED = "needs_runtime_verification"


@dataclass(frozen=True)
class RuntimeResolution:
    verdict: str  # confirmed | ruled_out | needs_runtime_verification (unchanged)
    evidence: dict | None  # a runtime_log evidence item on a resolved verdict, else None
    reason: str


def _log(text: str) -> dict:
    return {"kind": "runtime_log", "snippet": text, "source": "runtime_check"}


def _line(r: ProbeResult) -> str:
    cred = "with credential" if r.request.authenticated else "no credential"
    return f"{r.request.method} {r.request.path} ({cred}) → {r.status}"


def resolve_runtime_verdict(results: list[ProbeResult]) -> RuntimeResolution:
    """Decide from the probe results. Only the no-credential requests that
    produced a real HTTP response are decisive."""
    unauth = [r for r in results if not r.request.authenticated and r.status]

    exposed = [r for r in unauth if 200 <= r.status < 300]
    if exposed:
        detail = "; ".join(_line(r) for r in exposed)
        return RuntimeResolution(
            "confirmed", _log(f"{detail} → sensitive response served without authentication"),
            "unauthenticated request returned a 2xx response",
        )

    if unauth and all(r.status in (401, 403) for r in unauth):
        detail = "; ".join(_line(r) for r in unauth)
        return RuntimeResolution(
            "ruled_out", _log(f"{detail} → access control enforced at runtime"),
            "unauthenticated request was rejected (401/403)",
        )

    # No conclusive no-credential response (redirect, 404, 5xx, transport error,
    # or nothing ran). Leave the finding for a human or a later probe.
    return RuntimeResolution(_UNRESOLVED, None, "no conclusive runtime signal")

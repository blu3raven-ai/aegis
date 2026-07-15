"""Turn observed detonation egress into a verdict.

Detonation runs a setup/skill entry with deps already installed and no network
route off-box, so the flow needs nothing from outside. Any egress it attempts is
therefore behavior a benign setup never produces — a reverse shell's outbound
connect, a DNS-delivered payload's lookup. So the rule is simple and conservative:

  any egress attempt → malicious (confirmed at runtime); none → nothing to say.

'No egress' does NOT clear the target — a payload can lie dormant, and absence of
runtime egress is not proof of safety. Static findings stand on their own; this
only ever ADDS a runtime-confirmed finding, never suppresses one.
"""
from __future__ import annotations

from dataclasses import dataclass

from runner.sandbox.honeypot import EgressEvent

_MAX_EVIDENCE = 10  # cap the evidence list; the count in the summary is the full tally


@dataclass(frozen=True)
class DetonationVerdict:
    malicious: bool
    evidence: list[dict]  # runtime_log evidence items (empty when not malicious)
    summary: str


def _evidence_line(event: EgressEvent) -> dict:
    if event.proto == "dns":
        detail = f"DNS {event.detail or 'query'} lookup of {event.target}"
    else:
        detail = f"outbound TCP connection to {event.target}"
    return {"kind": "runtime_log", "snippet": f"detonation: {detail}", "source": "detonation"}


def verdict_from_egress(events: list[EgressEvent], *, entry_source: str) -> DetonationVerdict:
    """Malicious iff the detonated entry attempted any egress. Evidence is one
    runtime_log line per attempt (capped), with the full count in the summary."""
    if not events:
        return DetonationVerdict(False, [], f"detonation of {entry_source}: no egress observed")
    evidence = [_evidence_line(e) for e in events[:_MAX_EVIDENCE]]
    summary = (
        f"detonation of {entry_source}: {len(events)} egress attempt(s) at runtime "
        f"in an egress-denied sandbox — a benign setup makes none"
    )
    return DetonationVerdict(True, evidence, summary)

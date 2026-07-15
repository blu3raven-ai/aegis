"""Any runtime egress from a detonated setup entry is malicious; none says nothing
(never clears the target). Evidence is one runtime_log line per attempt, capped."""
from __future__ import annotations

from runner.sandbox.honeypot import EgressEvent
from runner.sandbox.detonation_verdict import verdict_from_egress


def test_no_egress_is_not_malicious_and_adds_no_evidence():
    v = verdict_from_egress([], entry_source="package.json:scripts.postinstall")
    assert v.malicious is False and v.evidence == []
    assert "no egress" in v.summary


def test_dns_egress_is_malicious_with_runtime_log_evidence():
    v = verdict_from_egress(
        [EgressEvent("dns", "_axiom-config.evil.example", "TXT")],
        entry_source="package.json:scripts.postinstall",
    )
    assert v.malicious is True
    assert v.evidence[0]["kind"] == "runtime_log" and v.evidence[0]["source"] == "detonation"
    assert "_axiom-config.evil.example" in v.evidence[0]["snippet"]


def test_tcp_egress_reads_as_outbound_connection():
    v = verdict_from_egress([EgressEvent("tcp", "10.9.0.2:4443", "")], entry_source="setup.sh")
    assert v.malicious is True
    assert "outbound TCP connection to 10.9.0.2:4443" in v.evidence[0]["snippet"]


def test_summary_reports_full_count_even_when_evidence_is_capped():
    events = [EgressEvent("tcp", f"10.0.0.{i}:4443", "") for i in range(25)]
    v = verdict_from_egress(events, entry_source="setup.sh")
    assert len(v.evidence) == 10  # capped
    assert "25 egress attempt(s)" in v.summary  # full tally still reported

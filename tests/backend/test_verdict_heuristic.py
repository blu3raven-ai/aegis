"""Unit tests for the provisional confidence (verdict) heuristic."""
from src.shared.verdict_heuristic import heuristic_verdict


def test_high_scanner_confidence_is_needs_verify():
    assert heuristic_verdict("high", has_cve=False) == "needs_verify"
    assert heuristic_verdict("HIGH", has_cve=False) == "needs_verify"  # case-insensitive
    assert heuristic_verdict(" High ", has_cve=False) == "needs_verify"  # trimmed


def test_cve_backed_finding_is_needs_verify_even_without_confidence():
    assert heuristic_verdict(None, has_cve=True) == "needs_verify"
    assert heuristic_verdict("", has_cve=True) == "needs_verify"


def test_low_signal_findings_are_possible():
    assert heuristic_verdict("medium", has_cve=False) == "possible"
    assert heuristic_verdict("low", has_cve=False) == "possible"
    assert heuristic_verdict(None, has_cve=False) == "possible"
    assert heuristic_verdict("", has_cve=False) == "possible"


def test_never_fabricates_confirmed():
    # confirmed means a concrete exploit was articulated — only Argus asserts it.
    for conf in (None, "", "low", "medium", "high", "garbage"):
        for cve in (True, False):
            assert heuristic_verdict(conf, has_cve=cve) in ("needs_verify", "possible")

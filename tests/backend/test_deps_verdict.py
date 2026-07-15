"""Unit tests for the reachability-aware categorical verdict for deps findings."""
import pytest
from src.shared.deps_verdict import SUPPRESSIBLE_CWES, deps_verdict


def test_suppressible_cwes_set_membership():
    assert "CWE-89" in SUPPRESSIBLE_CWES
    assert "CWE-327" not in SUPPRESSIBLE_CWES


def test_kev_listed_always_needs_verify_even_with_no_path_and_suppressible_cwe():
    # KEV-listed CVEs are actively exploited — never hide them.
    assert deps_verdict("no_path", kev_listed=True, cwes=["CWE-89"]) == "needs_verify"
    assert deps_verdict("no_path", kev_listed=True, cwes=[]) == "needs_verify"
    assert deps_verdict("reachable", kev_listed=True, cwes=["CWE-89"]) == "needs_verify"
    assert deps_verdict("unknown", kev_listed=True, cwes=[]) == "needs_verify"


def test_reachable_is_needs_verify():
    assert deps_verdict("reachable", kev_listed=False, cwes=[]) == "needs_verify"
    assert deps_verdict("reachable", kev_listed=False, cwes=["CWE-89"]) == "needs_verify"
    assert deps_verdict("reachable", kev_listed=False, cwes=["CWE-327"]) == "needs_verify"


def test_unknown_is_needs_verify():
    # Ungrounded label: runner could not determine reachability.
    assert deps_verdict("unknown", kev_listed=False, cwes=[]) == "needs_verify"
    assert deps_verdict("unknown", kev_listed=False, cwes=["CWE-89"]) == "needs_verify"


def test_no_path_suppressible_cwe_is_ruled_out():
    # CWE class known to have low LLM miss rate → safe to hide.
    assert deps_verdict("no_path", kev_listed=False, cwes=["CWE-89"]) == "ruled_out"
    assert deps_verdict("no_path", kev_listed=False, cwes=["CWE-78"]) == "ruled_out"
    assert deps_verdict("no_path", kev_listed=False, cwes=["CWE-79"]) == "ruled_out"
    assert deps_verdict("no_path", kev_listed=False, cwes=["CWE-22"]) == "ruled_out"
    assert deps_verdict("no_path", kev_listed=False, cwes=["CWE-918"]) == "ruled_out"


def test_no_path_non_suppressible_cwe_is_possible():
    # High-miss class (e.g. weak crypto): visible but de-emphasised.
    assert deps_verdict("no_path", kev_listed=False, cwes=["CWE-327"]) == "possible"


def test_no_path_no_cwe_is_possible():
    # No CWE information — can't confirm it's safe to suppress.
    assert deps_verdict("no_path", kev_listed=False, cwes=[]) == "possible"
    assert deps_verdict("no_path", kev_listed=False, cwes=None) == "possible"


def test_no_path_mixed_cwes_suppressible_wins():
    # If any CWE in the list is suppressible, rule it out.
    assert deps_verdict("no_path", kev_listed=False, cwes=["CWE-327", "CWE-89"]) == "ruled_out"

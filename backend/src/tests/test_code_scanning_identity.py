"""SAST finding identity — must be stable across line drift.

Regression for the re-scan bug: when an unrelated edit shifted a finding's line
number, the old line-based identity key changed, so the previous finding looked
"vanished" (auto-fixed) and the moved result was inserted as new — losing triage
state and resetting SLA clocks. Identity now keys on a snippet fingerprint.
"""
from __future__ import annotations

from src.code_scanning.ingest import (
    code_finding_identity,
    finding_identity_key,
    identity_key_from_finding,
)
from src.code_scanning.lifecycle import code_scanning_hooks


def _raw(start_line: int, snippet: str, *, rule="py.sqli", path="app/db.py"):
    return {
        "repo_full_name": "acme/api",
        "file_path": path,
        "rule_id": rule,
        "start_line": start_line,
        "snippet": snippet,
    }


def test_identity_stable_across_line_drift():
    """Same vuln, shifted down 40 lines by an unrelated edit — one finding."""
    before = code_scanning_hooks.compute_identity_key(_raw(12, "query(f'... {user_id}')"))
    after = code_scanning_hooks.compute_identity_key(_raw(52, "query(f'... {user_id}')"))
    assert before == after


def test_identity_distinguishes_distinct_snippets():
    """Two different sinks for the same rule in the same file stay separate."""
    a = code_scanning_hooks.compute_identity_key(_raw(12, "query(f'... {user_id}')"))
    b = code_scanning_hooks.compute_identity_key(_raw(30, "query(f'... {account}')"))
    assert a != b


def test_identity_normalizes_indentation():
    """Reindenting the matched line must not re-key the finding."""
    a = code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "    do_thing(x)")
    b = code_finding_identity("acme/api", "app/db.py", "py.sqli", 99, "do_thing(x)")
    assert a == b


def test_identity_falls_back_to_line_without_snippet():
    """No snippet → keep the legacy line-based key (no needless churn)."""
    k = code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "")
    assert k == "acme/api:app/db.py:py.sqli:12"
    # distinct lines remain distinct when there is nothing to fingerprint
    other = code_finding_identity("acme/api", "app/db.py", "py.sqli", 13, "")
    assert k != other


def test_identity_escapes_colons_in_components():
    k = code_finding_identity("acme/a:b", "x.py", "r", 1, "")
    assert k == "acme/a%3Ab:x.py:r:1"


def test_helpers_delegate_to_code_finding_identity():
    expected = code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "sink(x)")
    assert finding_identity_key("acme/api", "app/db.py", "py.sqli", 12, "sink(x)") == expected
    assert identity_key_from_finding(_raw(12, "sink(x)")) == expected

"""Tests for computing new-in-PR findings."""
from __future__ import annotations

from src.pr_feedback.diff import compute_new_in_pr


def _f(fp: str, sev: str = "high", title: str = "") -> dict:
    return {"fingerprint": fp, "severity": sev, "title": title or fp}


def test_first_scan_on_base_returns_all_head_findings_as_new():
    head = [_f("a"), _f("b")]
    new, is_first = compute_new_in_pr(head_findings=head, base_findings=None)
    assert is_first is True
    assert {f["fingerprint"] for f in new} == {"a", "b"}


def test_filters_out_findings_already_in_base():
    base = [_f("a"), _f("b")]
    head = [_f("a"), _f("b"), _f("c")]
    new, is_first = compute_new_in_pr(head_findings=head, base_findings=base)
    assert is_first is False
    assert [f["fingerprint"] for f in new] == ["c"]


def test_empty_head_returns_empty_new():
    new, is_first = compute_new_in_pr(head_findings=[], base_findings=[_f("a")])
    assert new == []
    assert is_first is False


def test_empty_base_list_is_distinct_from_none():
    # An empty base list means "we scanned, no findings". Not the same as no scan.
    head = [_f("a")]
    new, is_first = compute_new_in_pr(head_findings=head, base_findings=[])
    assert is_first is False
    assert [f["fingerprint"] for f in new] == ["a"]

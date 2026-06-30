"""Contract tests for the subject-agnostic condition engine.

`evaluate_condition` drives rule matching across the product (findings rules,
data-retention, etc.), so its operator semantics, severity-rank ordinals,
all/any grouping (including the vacuous-truth cases), and error paths are
locked here. The subject is a plain dict and the getter is a dict lookup.
"""
from __future__ import annotations

import pytest

from src.rules_engine.conditions import evaluate_condition


def _ev(condition, subject):
    return evaluate_condition(condition, subject, lambda subj, field: subj.get(field))


# ----- leaf operators -------------------------------------------------------

def test_eq_neq():
    assert _ev({"field": "tool", "op": "eq", "value": "semgrep"}, {"tool": "semgrep"})
    assert not _ev({"field": "tool", "op": "eq", "value": "semgrep"}, {"tool": "trivy"})
    assert _ev({"field": "tool", "op": "neq", "value": "semgrep"}, {"tool": "trivy"})
    assert not _ev({"field": "tool", "op": "neq", "value": "semgrep"}, {"tool": "semgrep"})


def test_in_nin():
    cond = {"field": "tool", "op": "in", "value": ["semgrep", "trivy"]}
    assert _ev(cond, {"tool": "trivy"})
    assert not _ev(cond, {"tool": "grype"})
    ncond = {"field": "tool", "op": "nin", "value": ["semgrep", "trivy"]}
    assert _ev(ncond, {"tool": "grype"})
    assert not _ev(ncond, {"tool": "semgrep"})


def test_contains_on_list_field():
    cond = {"field": "tags", "op": "contains", "value": "kev"}
    assert _ev(cond, {"tags": ["kev", "epss"]})
    assert not _ev(cond, {"tags": ["epss"]})


def test_contains_on_string_field_is_substring():
    cond = {"field": "title", "op": "contains", "value": "SQL"}
    assert _ev(cond, {"title": "SQL injection"})
    assert not _ev(cond, {"title": "XSS"})


def test_not_contains_on_list_and_string():
    assert _ev({"field": "tags", "op": "not_contains", "value": "kev"}, {"tags": ["epss"]})
    assert not _ev({"field": "tags", "op": "not_contains", "value": "kev"}, {"tags": ["kev"]})
    assert _ev({"field": "title", "op": "not_contains", "value": "SQL"}, {"title": "XSS"})
    assert not _ev({"field": "title", "op": "not_contains", "value": "SQL"}, {"title": "SQL injection"})


def test_ordinal_numeric():
    assert _ev({"field": "score", "op": "gt", "value": 7.0}, {"score": 9.1})
    assert _ev({"field": "score", "op": "gte", "value": 9.1}, {"score": 9.1})
    assert _ev({"field": "score", "op": "lt", "value": 7.0}, {"score": 3.2})
    assert _ev({"field": "score", "op": "lte", "value": 3.2}, {"score": 3.2})
    assert not _ev({"field": "score", "op": "gt", "value": 9.1}, {"score": 3.2})


def test_ordinal_severity_strings_use_rank():
    # critical(4) > high(3) > medium(2) > low(1) > info(0) > none(-1)
    assert _ev({"field": "severity", "op": "gte", "value": "high"}, {"severity": "critical"})
    assert _ev({"field": "severity", "op": "gt", "value": "low"}, {"severity": "high"})
    assert not _ev({"field": "severity", "op": "gt", "value": "high"}, {"severity": "medium"})
    assert _ev({"field": "severity", "op": "lt", "value": "critical"}, {"severity": "low"})
    assert _ev({"field": "severity", "op": "gt", "value": "none"}, {"severity": "info"})


def test_unknown_operator_raises():
    with pytest.raises(ValueError, match="unknown operator"):
        _ev({"field": "tool", "op": "matches", "value": "x"}, {"tool": "x"})


# ----- grouping -------------------------------------------------------------

def test_all_is_and():
    cond = {"all": [
        {"field": "tool", "op": "eq", "value": "semgrep"},
        {"field": "severity", "op": "gte", "value": "high"},
    ]}
    assert _ev(cond, {"tool": "semgrep", "severity": "critical"})
    assert not _ev(cond, {"tool": "semgrep", "severity": "low"})


def test_any_is_or():
    cond = {"any": [
        {"field": "tool", "op": "eq", "value": "semgrep"},
        {"field": "severity", "op": "gte", "value": "critical"},
    ]}
    assert _ev(cond, {"tool": "trivy", "severity": "critical"})
    assert not _ev(cond, {"tool": "trivy", "severity": "low"})


def test_nested_groups():
    cond = {"all": [
        {"field": "tool", "op": "eq", "value": "semgrep"},
        {"any": [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "tags", "op": "contains", "value": "kev"},
        ]},
    ]}
    assert _ev(cond, {"tool": "semgrep", "severity": "low", "tags": ["kev"]})
    assert not _ev(cond, {"tool": "semgrep", "severity": "low", "tags": []})


def test_vacuous_truth_cases():
    # Empty condition, empty all, and (specially) empty any all match every subject.
    assert _ev({}, {"anything": 1})
    assert _ev({"all": []}, {"anything": 1})
    assert _ev({"any": []}, {"anything": 1})  # special-cased to True, not any([])==False


# ----- leaf validation ------------------------------------------------------

def test_malformed_leaf_raises():
    with pytest.raises(ValueError, match="malformed leaf"):
        _ev({"op": "eq", "value": "x"}, {})  # missing field
    with pytest.raises(ValueError, match="malformed leaf"):
        _ev({"field": "tool", "value": "x"}, {})  # missing op


def test_getter_receives_subject_and_field_name():
    seen = {}

    def getter(subj, field):
        seen["args"] = (subj, field)
        return subj[field]

    subject = {"tool": "semgrep"}
    evaluate_condition({"field": "tool", "op": "eq", "value": "semgrep"}, subject, getter)
    assert seen["args"] == (subject, "tool")

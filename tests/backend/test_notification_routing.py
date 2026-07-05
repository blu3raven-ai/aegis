"""Tests for the Phase 42 notification routing engine.

Covers:
- evaluate_condition: all operators, all/any groupings, nested trees
- route_finding: priority ordering, first-match-wins, fallback (empty list),
  disabled rules skipped, malformed conditions skipped gracefully
"""
from __future__ import annotations

import pytest
from src.notifications.routing import Finding, Rule, evaluate_condition, route_finding


# ── Helpers ───────────────────────────────────────────────────────────────────


def _finding(**kwargs) -> Finding:
    defaults = dict(
        severity="medium",
        scanner="dependencies",
        repo_id="repo-123",
        repo_labels=["production", "backend"],
        cve_id=None,
        chain_role=None,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _rule(
    id: str = "r1",
    priority: int = 10,
    channel_id: int = 1,
    conditions: dict | None = None,
    enabled: bool = True,
) -> Rule:
    return Rule(
        id=id,
        name=f"rule-{id}",
        enabled=enabled,
        priority=priority,
        channel_id=channel_id,
        conditions=conditions or {},
        org_id="example-org",
    )


# ── evaluate_condition: leaf operators ────────────────────────────────────────


def test_eq_match():
    f = _finding(severity="critical")
    assert evaluate_condition({"field": "severity", "op": "eq", "value": "critical"}, f) is True


def test_eq_no_match():
    f = _finding(severity="high")
    assert evaluate_condition({"field": "severity", "op": "eq", "value": "critical"}, f) is False


def test_neq_match():
    f = _finding(scanner="secrets")
    assert evaluate_condition({"field": "scanner", "op": "neq", "value": "dependencies"}, f) is True


def test_neq_no_match():
    f = _finding(scanner="dependencies")
    assert evaluate_condition({"field": "scanner", "op": "neq", "value": "dependencies"}, f) is False


def test_in_match():
    f = _finding(severity="high")
    cond = {"field": "severity", "op": "in", "value": ["critical", "high"]}
    assert evaluate_condition(cond, f) is True


def test_in_no_match():
    f = _finding(severity="low")
    cond = {"field": "severity", "op": "in", "value": ["critical", "high"]}
    assert evaluate_condition(cond, f) is False


def test_nin_match():
    f = _finding(severity="low")
    cond = {"field": "severity", "op": "nin", "value": ["critical", "high"]}
    assert evaluate_condition(cond, f) is True


def test_nin_no_match():
    f = _finding(severity="critical")
    cond = {"field": "severity", "op": "nin", "value": ["critical", "high"]}
    assert evaluate_condition(cond, f) is False


def test_contains_list():
    f = _finding(repo_labels=["production", "backend"])
    cond = {"field": "repo_labels", "op": "contains", "value": "production"}
    assert evaluate_condition(cond, f) is True


def test_contains_list_no_match():
    f = _finding(repo_labels=["staging"])
    cond = {"field": "repo_labels", "op": "contains", "value": "production"}
    assert evaluate_condition(cond, f) is False


def test_not_contains_list():
    f = _finding(repo_labels=["staging"])
    cond = {"field": "repo_labels", "op": "not_contains", "value": "production"}
    assert evaluate_condition(cond, f) is True


def test_not_contains_list_no_match():
    f = _finding(repo_labels=["production", "backend"])
    cond = {"field": "repo_labels", "op": "not_contains", "value": "production"}
    assert evaluate_condition(cond, f) is False


def test_gt_severity():
    f = _finding(severity="critical")  # rank 4
    cond = {"field": "severity", "op": "gt", "value": "high"}  # rank 3
    assert evaluate_condition(cond, f) is True


def test_gt_severity_no_match():
    f = _finding(severity="medium")  # rank 2
    cond = {"field": "severity", "op": "gt", "value": "high"}  # rank 3
    assert evaluate_condition(cond, f) is False


def test_gte_severity_equal():
    f = _finding(severity="high")
    cond = {"field": "severity", "op": "gte", "value": "high"}
    assert evaluate_condition(cond, f) is True


def test_lt_severity():
    f = _finding(severity="low")  # rank 1
    cond = {"field": "severity", "op": "lt", "value": "medium"}  # rank 2
    assert evaluate_condition(cond, f) is True


def test_lte_severity_equal():
    f = _finding(severity="medium")
    cond = {"field": "severity", "op": "lte", "value": "medium"}
    assert evaluate_condition(cond, f) is True


# ── evaluate_condition: all/any groupings ─────────────────────────────────────


def test_all_both_true():
    f = _finding(severity="critical", scanner="secrets")
    cond = {
        "all": [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "scanner", "op": "eq", "value": "secrets"},
        ]
    }
    assert evaluate_condition(cond, f) is True


def test_all_one_false():
    f = _finding(severity="high", scanner="secrets")
    cond = {
        "all": [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "scanner", "op": "eq", "value": "secrets"},
        ]
    }
    assert evaluate_condition(cond, f) is False


def test_any_one_true():
    f = _finding(severity="low")
    cond = {
        "any": [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "severity", "op": "eq", "value": "low"},
        ]
    }
    assert evaluate_condition(cond, f) is True


def test_any_none_true():
    f = _finding(severity="medium")
    cond = {
        "any": [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "severity", "op": "eq", "value": "high"},
        ]
    }
    assert evaluate_condition(cond, f) is False


def test_empty_all_vacuous_true():
    assert evaluate_condition({"all": []}, _finding()) is True


def test_empty_any_vacuous_true():
    assert evaluate_condition({"any": []}, _finding()) is True


def test_empty_condition_vacuous_true():
    assert evaluate_condition({}, _finding()) is True


def test_nested_all_inside_any():
    f = _finding(severity="critical", scanner="secrets", repo_labels=["production"])
    cond = {
        "any": [
            {
                "all": [
                    {"field": "severity", "op": "eq", "value": "critical"},
                    {"field": "scanner", "op": "eq", "value": "secrets"},
                ]
            },
            {"field": "repo_labels", "op": "contains", "value": "staging"},
        ]
    }
    assert evaluate_condition(cond, f) is True


def test_nested_all_inside_any_no_match():
    f = _finding(severity="high", scanner="dependencies", repo_labels=["staging"])
    cond = {
        "any": [
            {
                "all": [
                    {"field": "severity", "op": "eq", "value": "critical"},
                    {"field": "scanner", "op": "eq", "value": "secrets"},
                ]
            },
            {"field": "repo_labels", "op": "contains", "value": "production"},
        ]
    }
    assert evaluate_condition(cond, f) is False


# ── evaluate_condition: error paths ──────────────────────────────────────────


def test_unknown_field_raises():
    with pytest.raises(ValueError, match="unknown finding field"):
        evaluate_condition({"field": "nonexistent", "op": "eq", "value": "x"}, _finding())


def test_unknown_op_raises():
    with pytest.raises(ValueError, match="unknown operator"):
        evaluate_condition({"field": "severity", "op": "regex", "value": ".*"}, _finding())


def test_malformed_leaf_raises():
    with pytest.raises(ValueError, match="malformed leaf"):
        evaluate_condition({"notafield": "x"}, _finding())


# ── route_finding ─────────────────────────────────────────────────────────────


def test_route_first_match_wins():
    f = _finding(severity="critical")
    rules = [
        _rule(id="r1", priority=10, channel_id=1, conditions={"field": "severity", "op": "eq", "value": "critical"}),
        _rule(id="r2", priority=20, channel_id=2, conditions={"field": "severity", "op": "eq", "value": "critical"}),
    ]
    assert route_finding(f, rules) == [1]


def test_route_priority_order():
    f = _finding(severity="high")
    rules = [
        _rule(id="r2", priority=20, channel_id=2, conditions={"field": "severity", "op": "eq", "value": "high"}),
        _rule(id="r1", priority=5, channel_id=1, conditions={"field": "severity", "op": "eq", "value": "high"}),
    ]
    # r1 has lower priority number → higher precedence
    assert route_finding(f, rules) == [1]


def test_route_no_match_returns_empty():
    f = _finding(severity="low")
    rules = [
        _rule(id="r1", priority=10, channel_id=1, conditions={"field": "severity", "op": "eq", "value": "critical"}),
    ]
    assert route_finding(f, rules) == []


def test_route_disabled_rule_skipped():
    f = _finding(severity="critical")
    rules = [
        _rule(id="r1", priority=1, channel_id=1, conditions={"field": "severity", "op": "eq", "value": "critical"}, enabled=False),
        _rule(id="r2", priority=2, channel_id=2, conditions={"field": "severity", "op": "eq", "value": "critical"}, enabled=True),
    ]
    assert route_finding(f, rules) == [2]


def test_route_empty_rules_returns_empty():
    assert route_finding(_finding(), []) == []


def test_route_malformed_condition_skipped_gracefully():
    f = _finding(severity="critical")
    bad_rule = _rule(
        id="bad",
        priority=1,
        channel_id=99,
        conditions={"field": "nonexistent_field", "op": "eq", "value": "x"},
    )
    good_rule = _rule(
        id="good",
        priority=2,
        channel_id=1,
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    # bad_rule raises ValueError → skipped; good_rule matches
    result = route_finding(f, [bad_rule, good_rule])
    assert result == [1]


def test_route_catch_all_empty_conditions():
    # An empty conditions dict evaluates to True — useful as a catch-all rule
    f = _finding(severity="info")
    rules = [_rule(id="catch-all", priority=999, channel_id=5, conditions={})]
    assert route_finding(f, rules) == [5]

"""Unit tests for notifications.routing.route_finding.

Pure in-memory dispatch logic — no DB. These tests lock the "first match wins"
semantic plus the priority ordering that downstream callers depend on when
configuring overlapping rules.
"""
from __future__ import annotations

from src.notifications.routing import Finding, Rule, evaluate_condition, route_finding




def _rule(
    *,
    id: str,
    channel_id: int,
    conditions: dict,
    priority: int = 100,
    enabled: bool = True,
    name: str | None = None,
) -> Rule:
    return Rule(
        id=id,
        name=name or id,
        enabled=enabled,
        priority=priority,
        channel_id=channel_id,
        conditions=conditions,
    )




def test_route_finding_no_rules_returns_empty():
    finding = Finding(severity="high", scanner="trivy", repo_id="repo-1")
    assert route_finding(finding, []) == []


def test_route_finding_no_enabled_rules_returns_empty():
    finding = Finding(severity="high", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(id="r1", channel_id=1, conditions={}, enabled=False),
    ]
    assert route_finding(finding, rules) == []


def test_route_finding_match_by_severity_eq_returns_channel():
    finding = Finding(severity="critical", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-critical",
            channel_id=42,
            conditions={"field": "severity", "op": "eq", "value": "critical"},
        ),
    ]
    assert route_finding(finding, rules) == [42]


def test_route_finding_match_by_severity_gte_using_rank_map():
    # Severity comparisons use the rank map so "high >= medium" works without
    # the caller having to enumerate every level.
    finding = Finding(severity="high", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-gte-med",
            channel_id=7,
            conditions={"field": "severity", "op": "gte", "value": "medium"},
        ),
    ]
    assert route_finding(finding, rules) == [7]


def test_route_finding_match_by_scanner_in_list():
    finding = Finding(severity="low", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-scanner",
            channel_id=2,
            conditions={"field": "scanner", "op": "in", "value": ["trivy", "grype"]},
        ),
    ]
    assert route_finding(finding, rules) == [2]


def test_route_finding_match_by_repo_label_contains():
    finding = Finding(
        severity="medium", scanner="semgrep", repo_id="repo-1",
        repo_labels=["frontend", "critical-path"],
    )
    rules = [
        _rule(
            id="r-label",
            channel_id=3,
            conditions={"field": "repo_labels", "op": "contains", "value": "critical-path"},
        ),
    ]
    assert route_finding(finding, rules) == [3]


def test_route_finding_no_match_returns_empty_list_for_fallback_fanout():
    # The router_event layer falls back to event-filter fanout when this is
    # empty — locking the contract that no match means [] (not None).
    finding = Finding(severity="info", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-only-critical",
            channel_id=1,
            conditions={"field": "severity", "op": "eq", "value": "critical"},
        ),
    ]
    assert route_finding(finding, rules) == []




def test_route_finding_first_match_wins_by_priority_ascending():
    # Both rules match, but the one with priority=1 must claim the finding.
    finding = Finding(severity="critical", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-low-prio",
            channel_id=99,
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            priority=100,
        ),
        _rule(
            id="r-high-prio",
            channel_id=42,
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            priority=1,
        ),
    ]
    assert route_finding(finding, rules) == [42]


def test_route_finding_disabled_rule_skipped_even_if_priority_is_lower():
    # A disabled high-priority rule must NOT shadow an enabled lower-priority
    # one — otherwise toggling enabled wouldn't actually disable the rule.
    finding = Finding(severity="critical", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-disabled",
            channel_id=99,
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            priority=1,
            enabled=False,
        ),
        _rule(
            id="r-enabled",
            channel_id=42,
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            priority=10,
        ),
    ]
    assert route_finding(finding, rules) == [42]


def test_route_finding_malformed_condition_doesnt_block_next_rule():
    # If a rule has a broken predicate tree, the engine must swallow the
    # exception and continue evaluating the next rule.
    finding = Finding(severity="critical", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-broken",
            channel_id=1,
            conditions={"field": "severity", "op": "bogus-op", "value": "critical"},
            priority=1,
        ),
        _rule(
            id="r-good",
            channel_id=7,
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            priority=2,
        ),
    ]
    assert route_finding(finding, rules) == [7]


def test_route_finding_match_by_all_grouping_with_severity_and_scanner():
    finding = Finding(severity="high", scanner="trivy", repo_id="repo-1")
    rules = [
        _rule(
            id="r-and",
            channel_id=5,
            conditions={
                "all": [
                    {"field": "severity", "op": "gte", "value": "high"},
                    {"field": "scanner", "op": "eq", "value": "trivy"},
                ],
            },
        ),
    ]
    assert route_finding(finding, rules) == [5]


def test_route_finding_any_grouping_matches_when_one_child_matches():
    finding = Finding(severity="low", scanner="semgrep", repo_id="repo-1")
    rules = [
        _rule(
            id="r-or",
            channel_id=8,
            conditions={
                "any": [
                    {"field": "severity", "op": "eq", "value": "critical"},
                    {"field": "scanner", "op": "eq", "value": "semgrep"},
                ],
            },
        ),
    ]
    assert route_finding(finding, rules) == [8]


def test_route_finding_excludes_match_using_nin_on_repo_labels():
    finding = Finding(
        severity="critical", scanner="trivy", repo_id="repo-1",
        repo_labels=["frontend"],
    )
    rules = [
        _rule(
            id="r-not-internal",
            channel_id=9,
            conditions={"field": "repo_labels", "op": "not_contains", "value": "internal"},
        ),
    ]
    assert route_finding(finding, rules) == [9]




def test_evaluate_condition_unknown_field_raises_for_finding_subject():
    # The whitelist guards against rules referencing fields that don't exist
    # on Finding — silent False would let typos pass routing rules.
    import pytest

    finding = Finding(severity="critical", scanner="trivy", repo_id="repo-1")
    with pytest.raises(ValueError, match="unknown finding field"):
        evaluate_condition(
            {"field": "not_a_field", "op": "eq", "value": "x"},
            finding,
        )


def test_evaluate_condition_empty_dict_is_vacuously_true():
    # A rule with no conditions acts as a catch-all so admins can route
    # "everything else" to a default channel.
    finding = Finding(severity="info", scanner="trivy", repo_id="repo-1")
    assert evaluate_condition({}, finding) is True

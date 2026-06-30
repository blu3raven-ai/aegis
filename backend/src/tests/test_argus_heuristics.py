"""Unit coverage for the Argus heuristic fallbacks.

These local approximations fire when Argus is unconfigured or unreachable, so
their formulas are the operator-visible contract for how a finding gets scored
or a gate gets decided without the remote. Pin the documented behaviour.
"""
from __future__ import annotations

import pytest

from src.argus.heuristics import (
    empty_rule_pack,
    heuristic_explain,
    heuristic_go_no_go,
    heuristic_score,
)


@pytest.mark.parametrize(
    "severity,expected_base",
    [
        ("critical", 90.0),
        ("high", 70.0),
        ("medium", 45.0),
        ("low", 20.0),
        ("informational", 5.0),
        ("info", 5.0),
    ],
)
def test_score_base_by_severity(severity, expected_base):
    assert heuristic_score(severity) == expected_base


def test_score_is_case_insensitive():
    assert heuristic_score("CRITICAL") == 90.0
    assert heuristic_score("High") == 70.0


def test_score_unknown_severity_defaults_to_low_base():
    # Unknown / empty / None severities fall back to the conservative 20.0 base.
    assert heuristic_score("bogus") == 20.0
    assert heuristic_score("") == 20.0
    assert heuristic_score(None) == 20.0  # type: ignore[arg-type]


def test_score_epss_adds_up_to_ten_points():
    # EPSS is [0,1]; multiplier is 10, so epss=1.0 adds a full 10 points.
    assert heuristic_score("high", epss=1.0) == 80.0
    assert heuristic_score("high", epss=0.5) == 75.0


def test_score_includes_reachability_and_chain_bonuses():
    assert heuristic_score("medium", reachability_bonus=5.0, chain_bonus=5.0) == 55.0


def test_score_is_capped_at_100():
    # critical(90) + epss(10) + bonuses(20) = 120 raw, clamped to 100.
    assert heuristic_score(
        "critical", epss=1.0, reachability_bonus=10.0, chain_bonus=10.0
    ) == 100.0


def test_score_rounds_to_two_decimals():
    # high(70) + 0.333*10 = 73.33
    assert heuristic_score("high", epss=0.333) == 73.33


def test_go_no_go_blocks_on_critical_and_lists_blocker_ids():
    findings = [
        {"id": "F-1", "severity": "critical"},
        {"id": "F-2", "severity": "low"},
    ]
    out = heuristic_go_no_go(findings)
    assert out["decision"] == "block"
    assert out["blockers"] == ["F-1"]
    assert "critical" in out["rationale"].lower()


def test_go_no_go_critical_without_id_still_blocks_with_empty_blocker():
    out = heuristic_go_no_go([{"severity": "critical"}])
    assert out["decision"] == "block"
    assert out["blockers"] == []


def test_go_no_go_warns_on_high_without_blockers():
    out = heuristic_go_no_go([{"id": "F-9", "severity": "high"}])
    assert out["decision"] == "warn"
    # warn never carries blocker ids — only critical does.
    assert out["blockers"] == []


def test_go_no_go_allows_when_nothing_high_or_above():
    out = heuristic_go_no_go(
        [{"severity": "medium"}, {"severity": "low"}, {"severity": "info"}]
    )
    assert out["decision"] == "allow"
    assert out["blockers"] == []


def test_go_no_go_critical_wins_over_high():
    out = heuristic_go_no_go(
        [{"id": "H", "severity": "high"}, {"id": "C", "severity": "critical"}]
    )
    assert out["decision"] == "block"
    assert out["blockers"] == ["C"]


def test_go_no_go_empty_findings_allows():
    out = heuristic_go_no_go([])
    assert out["decision"] == "allow"


def test_explain_renders_counts_and_chain_type():
    text = heuristic_explain(
        {
            "chain_type": "cve_to_secret",
            "findings": [{}, {}, {}],
            "edges": [{}, {}],
        }
    )
    assert "cve_to_secret" in text
    assert "**3**" in text
    assert "**2**" in text


def test_explain_defaults_on_missing_fields():
    text = heuristic_explain({})
    assert "unknown" in text
    assert "**0**" in text


def test_empty_rule_pack_is_empty_dict():
    assert empty_rule_pack() == {}

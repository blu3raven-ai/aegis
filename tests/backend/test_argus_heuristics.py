"""Tests for argus.heuristics — fallback math and templating."""
from __future__ import annotations

import pytest

from src.argus.heuristics import (
    empty_rule_pack,
    heuristic_explain,
    heuristic_go_no_go,
    heuristic_score,
)


# ── heuristic_score ───────────────────────────────────────────────────────────


def test_score_critical_no_epss():
    score = heuristic_score("critical")
    assert score == 90.0


def test_score_high_no_epss():
    score = heuristic_score("high")
    assert score == 70.0


def test_score_medium_no_epss():
    score = heuristic_score("medium")
    assert score == 45.0


def test_score_low_no_epss():
    score = heuristic_score("low")
    assert score == 20.0


def test_score_epss_adds_bonus():
    # EPSS 1.0 should add 10 points
    score = heuristic_score("medium", epss=1.0)
    assert score == 55.0


def test_score_epss_partial():
    score = heuristic_score("medium", epss=0.5)
    assert score == 50.0


def test_score_reachability_bonus():
    score = heuristic_score("medium", reachability_bonus=5.0)
    assert score == 50.0


def test_score_chain_bonus():
    score = heuristic_score("medium", chain_bonus=5.0)
    assert score == 50.0


def test_score_capped_at_100():
    # Pile on all bonuses to verify cap
    score = heuristic_score("critical", epss=1.0, reachability_bonus=10.0, chain_bonus=10.0)
    assert score == 100.0


def test_score_unknown_severity_defaults_to_medium_base():
    # Unknown severities fall back to 20.0 (low base)
    score = heuristic_score("unknown_level")
    assert score == 20.0


def test_score_case_insensitive():
    assert heuristic_score("CRITICAL") == heuristic_score("critical")
    assert heuristic_score("HIGH") == heuristic_score("high")


def test_score_returns_float():
    result = heuristic_score("medium", epss=0.3)
    assert isinstance(result, float)


# ── heuristic_go_no_go ────────────────────────────────────────────────────────


def test_go_no_go_allow_when_no_findings():
    result = heuristic_go_no_go([])
    assert result["decision"] == "allow"
    assert result["blockers"] == []


def test_go_no_go_allow_when_only_low_findings():
    findings = [{"id": "f1", "severity": "low"}, {"id": "f2", "severity": "medium"}]
    result = heuristic_go_no_go(findings)
    assert result["decision"] == "allow"
    assert result["blockers"] == []


def test_go_no_go_warn_when_high_finding():
    findings = [{"id": "f3", "severity": "high"}]
    result = heuristic_go_no_go(findings)
    assert result["decision"] == "warn"
    assert result["blockers"] == []
    assert "rationale" in result


def test_go_no_go_block_when_critical_finding():
    findings = [{"id": "f4", "severity": "critical"}]
    result = heuristic_go_no_go(findings)
    assert result["decision"] == "block"
    assert "f4" in result["blockers"]


def test_go_no_go_block_overrides_warn_with_mixed_severities():
    findings = [
        {"id": "f5", "severity": "high"},
        {"id": "f6", "severity": "critical"},
    ]
    result = heuristic_go_no_go(findings)
    assert result["decision"] == "block"
    assert "f6" in result["blockers"]
    assert "f5" not in result["blockers"]


def test_go_no_go_missing_id_still_blocks():
    findings = [{"severity": "critical"}]  # no id field
    result = heuristic_go_no_go(findings)
    assert result["decision"] == "block"
    assert result["blockers"] == []  # id not added when missing


def test_go_no_go_case_insensitive_severity():
    findings = [{"id": "f7", "severity": "CRITICAL"}]
    result = heuristic_go_no_go(findings)
    assert result["decision"] == "block"


# ── heuristic_explain ─────────────────────────────────────────────────────────


def test_explain_contains_chain_type():
    chain = {"chain_type": "cve_to_secret", "findings": [{}], "edges": []}
    result = heuristic_explain(chain)
    assert "cve_to_secret" in result


def test_explain_contains_finding_count():
    chain = {"chain_type": "any", "findings": [{"id": 1}, {"id": 2}], "edges": []}
    result = heuristic_explain(chain)
    assert "2" in result


def test_explain_contains_edge_count():
    chain = {"chain_type": "any", "findings": [], "edges": [{"from_id": 1, "to_id": 2}]}
    result = heuristic_explain(chain)
    assert "1" in result


def test_explain_is_markdown_string():
    chain = {"chain_type": "test", "findings": [], "edges": []}
    result = heuristic_explain(chain)
    assert isinstance(result, str)
    assert len(result) > 0


def test_explain_handles_missing_keys():
    result = heuristic_explain({})
    assert isinstance(result, str)


# ── empty_rule_pack ───────────────────────────────────────────────────────────


def test_empty_rule_pack_returns_dict():
    pack = empty_rule_pack()
    assert isinstance(pack, dict)
    assert len(pack) == 0

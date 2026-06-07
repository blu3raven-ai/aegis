"""Tests for the shared condition engine and subject getters.

Covers:
- ``evaluate_condition`` is subject-agnostic — works with finding, repo, and
  scan-result subjects when wired to the corresponding getter.
- Each subject getter raises ``ValueError`` for unknown field names and returns
  the right value for valid fields.
- The legacy ``src.notifications.routing.evaluate_condition`` import surface
  still works for callers that haven't migrated.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.rules_engine.conditions import evaluate_condition
from src.rules_engine.subjects import (
    RuleFindingSubject,
    RuleRepoSubject,
    RuleScanResultSubject,
    get_finding_field,
    get_repo_field,
    get_scan_result_field,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _finding(**overrides) -> RuleFindingSubject:
    defaults: dict = dict(
        finding_id=1,
        severity="critical",
        scanner="dependencies",
        repo_id="repo-1",
        repo_labels=["production", "backend"],
        repo_archived=False,
        cve_id="CVE-2024-1234",
        cwe_id="CWE-79",
        kev_matched=False,
        epss_score=0.3,
        file_path="src/app.py",
        age_days=5,
    )
    defaults.update(overrides)
    return RuleFindingSubject(**defaults)


def _repo(**overrides) -> RuleRepoSubject:
    defaults: dict = dict(
        repo_id="repo-1",
        repo_labels=["production"],
        tier="production",
        archived=False,
        scanners_with_coverage=["dependencies"],
        image_registry=None,
        last_scanned_at=None,
    )
    defaults.update(overrides)
    return RuleRepoSubject(**defaults)


def _scan_result(**overrides) -> RuleScanResultSubject:
    defaults: dict = dict(
        scan_id="scan-1",
        repo_id="repo-1",
        tool="dependencies",
        finished_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        age_days=10,
    )
    defaults.update(overrides)
    return RuleScanResultSubject(**defaults)


# ── Subject getter: finding ───────────────────────────────────────────────────


def test_get_finding_field_returns_value():
    f = _finding(severity="high")
    assert get_finding_field(f, "severity") == "high"


def test_get_finding_field_list_value():
    f = _finding(repo_labels=["production", "backend"])
    assert get_finding_field(f, "repo_labels") == ["production", "backend"]


def test_get_finding_field_unknown_raises():
    with pytest.raises(ValueError, match="unknown finding rule field"):
        get_finding_field(_finding(), "bogus_field")


def test_get_finding_field_identity_pk_is_not_exposed():
    # `finding_id` is intentionally excluded from the allowlist.
    with pytest.raises(ValueError, match="unknown finding rule field"):
        get_finding_field(_finding(), "finding_id")


# ── Subject getter: repo ──────────────────────────────────────────────────────


def test_get_repo_field_returns_value():
    r = _repo(tier="staging")
    assert get_repo_field(r, "tier") == "staging"


def test_get_repo_field_unknown_raises():
    with pytest.raises(ValueError, match="unknown repo rule field"):
        get_repo_field(_repo(), "severity")


# ── Subject getter: scan result ───────────────────────────────────────────────


def test_get_scan_result_field_returns_value():
    s = _scan_result(age_days=42)
    assert get_scan_result_field(s, "age_days") == 42


def test_get_scan_result_field_unknown_raises():
    with pytest.raises(ValueError, match="unknown scan-result rule field"):
        get_scan_result_field(_scan_result(), "severity")


# ── evaluate_condition: finding subject ───────────────────────────────────────


def test_evaluate_condition_finding_eq_match():
    f = _finding(severity="critical")
    cond = {"field": "severity", "op": "eq", "value": "critical"}
    assert evaluate_condition(cond, f, get_finding_field) is True


def test_evaluate_condition_finding_in_match():
    f = _finding(severity="high")
    cond = {"field": "severity", "op": "in", "value": ["critical", "high"]}
    assert evaluate_condition(cond, f, get_finding_field) is True


def test_evaluate_condition_finding_unknown_field_raises():
    f = _finding()
    cond = {"field": "nonexistent", "op": "eq", "value": "x"}
    with pytest.raises(ValueError, match="unknown finding rule field"):
        evaluate_condition(cond, f, get_finding_field)


def test_evaluate_condition_finding_age_gte():
    f = _finding(age_days=30)
    cond = {"field": "age_days", "op": "gte", "value": 14}
    assert evaluate_condition(cond, f, get_finding_field) is True


# ── evaluate_condition: repo subject ──────────────────────────────────────────


def test_evaluate_condition_repo_labels_contains():
    r = _repo(repo_labels=["production", "internal"])
    cond = {"field": "repo_labels", "op": "contains", "value": "production"}
    assert evaluate_condition(cond, r, get_repo_field) is True


def test_evaluate_condition_repo_labels_not_contains():
    r = _repo(repo_labels=["staging"])
    cond = {"field": "repo_labels", "op": "not_contains", "value": "production"}
    assert evaluate_condition(cond, r, get_repo_field) is True


def test_evaluate_condition_repo_tier_eq():
    r = _repo(tier="production")
    cond = {"field": "tier", "op": "eq", "value": "production"}
    assert evaluate_condition(cond, r, get_repo_field) is True


def test_evaluate_condition_repo_unknown_field_raises():
    r = _repo()
    cond = {"field": "severity", "op": "eq", "value": "critical"}
    with pytest.raises(ValueError, match="unknown repo rule field"):
        evaluate_condition(cond, r, get_repo_field)


# ── evaluate_condition: scan-result subject ───────────────────────────────────


def test_evaluate_condition_scan_result_age_gte():
    s = _scan_result(age_days=90)
    cond = {"field": "age_days", "op": "gte", "value": 90}
    assert evaluate_condition(cond, s, get_scan_result_field) is True


def test_evaluate_condition_scan_result_tool_eq():
    s = _scan_result(tool="secrets")
    cond = {"field": "tool", "op": "eq", "value": "secrets"}
    assert evaluate_condition(cond, s, get_scan_result_field) is True


def test_evaluate_condition_scan_result_unknown_field_raises():
    s = _scan_result()
    cond = {"field": "severity", "op": "eq", "value": "critical"}
    with pytest.raises(ValueError, match="unknown scan-result rule field"):
        evaluate_condition(cond, s, get_scan_result_field)


# ── Nested groupings across subject types ────────────────────────────────────


def test_evaluate_condition_finding_all_grouping():
    f = _finding(severity="critical", scanner="secrets")
    cond = {
        "all": [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "scanner", "op": "eq", "value": "secrets"},
        ]
    }
    assert evaluate_condition(cond, f, get_finding_field) is True


def test_evaluate_condition_repo_any_grouping():
    r = _repo(tier="production", archived=False)
    cond = {
        "any": [
            {"field": "tier", "op": "eq", "value": "staging"},
            {"field": "archived", "op": "eq", "value": False},
        ]
    }
    assert evaluate_condition(cond, r, get_repo_field) is True


def test_evaluate_condition_empty_condition_is_true():
    # Empty predicate evaluates True for every subject type
    assert evaluate_condition({}, _finding(), get_finding_field) is True
    assert evaluate_condition({}, _repo(), get_repo_field) is True
    assert evaluate_condition({}, _scan_result(), get_scan_result_field) is True


# ── Legacy import surface ─────────────────────────────────────────────────────


def test_legacy_evaluate_condition_import_still_works():
    """``src.notifications.routing.evaluate_condition`` should still resolve."""
    from src.notifications.routing import (
        Finding as LegacyFinding,
        evaluate_condition as legacy_evaluate,
    )

    finding = LegacyFinding(
        severity="critical",
        scanner="secrets",
        repo_id="repo-1",
    )
    assert legacy_evaluate(
        {"field": "severity", "op": "eq", "value": "critical"}, finding
    ) is True

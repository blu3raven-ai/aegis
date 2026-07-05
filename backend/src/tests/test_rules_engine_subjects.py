"""Contract tests for the Rules-engine subject getters.

The getters are an allowlist boundary: a rule predicate may only read fields
named in the per-subject allowlist, and the getter raises on anything else.
Notably `finding_id` (the PK) is intentionally excluded so rules can't predicate
on identity. These tests lock the allowlist semantics and the exclusion.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.rules_engine.subjects import (
    RuleFindingSubject,
    RuleRepoSubject,
    RuleScanResultSubject,
    get_finding_field,
    get_repo_field,
    get_scan_result_field,
)
from src.rules_engine import subjects as subj_mod


_NOW = datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)


def _finding() -> RuleFindingSubject:
    return RuleFindingSubject(
        finding_id=7, severity="high", scanner="semgrep", repo_id="acme/api",
        repo_labels=["prod"], repo_archived=False, cve_id="CVE-2025-1", cwe_id="CWE-89",
        kev_matched=True, epss_score=0.42, file_path="app/db.py", age_days=10,
    )


def _repo() -> RuleRepoSubject:
    return RuleRepoSubject(
        repo_id="acme/api", repo_labels=["prod"], tier="production", archived=False,
        scanners_with_coverage=["sast"], image_registry="ghcr", last_scanned_at=_NOW,
        last_scan_age_days=3,
    )


def _scan_result() -> RuleScanResultSubject:
    return RuleScanResultSubject(
        scan_id="scan-1", repo_id="acme/api", tool="dependencies", finished_at=_NOW, age_days=5,
    )


def test_each_allowlisted_field_is_gettable():
    # Every name in an allowlist must resolve to a real attribute (catches drift
    # where the allowlist names a field the dataclass doesn't have).
    f = _finding()
    for name in subj_mod._FINDING_FIELDS:
        assert get_finding_field(f, name) == getattr(f, name)
    r = _repo()
    for name in subj_mod._REPO_FIELDS:
        assert get_repo_field(r, name) == getattr(r, name)
    s = _scan_result()
    for name in subj_mod._SCAN_RESULT_FIELDS:
        assert get_scan_result_field(s, name) == getattr(s, name)


def test_unknown_field_raises():
    with pytest.raises(ValueError, match="unknown finding rule field"):
        get_finding_field(_finding(), "definitely_not_a_field")
    with pytest.raises(ValueError, match="unknown repo rule field"):
        get_repo_field(_repo(), "definitely_not_a_field")
    with pytest.raises(ValueError, match="unknown scan-result rule field"):
        get_scan_result_field(_scan_result(), "definitely_not_a_field")


def test_finding_id_pk_is_excluded():
    # The PK exists on the dataclass but is deliberately off the allowlist so a
    # rule cannot predicate on identity.
    assert "finding_id" not in subj_mod._FINDING_FIELDS
    with pytest.raises(ValueError, match="unknown finding rule field"):
        get_finding_field(_finding(), "finding_id")


def test_getter_returns_actual_values():
    f = _finding()
    assert get_finding_field(f, "severity") == "high"
    assert get_finding_field(f, "kev_matched") is True
    assert get_finding_field(f, "epss_score") == 0.42
    assert get_repo_field(_repo(), "tier") == "production"
    assert get_scan_result_field(_scan_result(), "tool") == "dependencies"


def test_dependency_scope_flows_from_detail_into_subject():
    """A deps finding's camelCase dependencyScope maps onto the subject field a
    rule predicates on, and evaluates through the conditions engine."""
    from src.shared.lifecycle import _build_subject_for_new_finding
    from src.rules_engine.conditions import evaluate_condition

    subj = _build_subject_for_new_finding(
        tool="dependencies", severity="high", repo="acme/api",
        detail={"dependencyScope": "dev", "cveId": "CVE-2025-9"},
    )
    assert subj.dependency_scope == "dev"
    assert get_finding_field(subj, "dependency_scope") == "dev"

    cond = {"field": "dependency_scope", "op": "eq", "value": "dev"}
    assert evaluate_condition(cond, subj, get_finding_field) is True
    prod = _build_subject_for_new_finding(
        tool="dependencies", severity="high", repo="acme/api", detail={"dependencyScope": "prod"},
    )
    assert evaluate_condition(cond, prod, get_finding_field) is False

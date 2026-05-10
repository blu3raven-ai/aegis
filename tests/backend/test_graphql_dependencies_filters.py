"""Tests for Dependencies findings resolver filter parameters."""
from __future__ import annotations

import pytest
from unittest.mock import patch

from src.graphql.dependencies_resolvers import dependencies_findings


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    pkg="lodash", eco="npm", severity="high", state="open",
    repo="org/repo-a", cvss=7.5, patched="4.17.21",
    created_at="2026-01-15T00:00:00Z", fixed_at=None, ghsa="GHSA-1",
):
    return {
        "state": state,
        "created_at": created_at,
        "first_seen_at": created_at,
        "fixed_at": fixed_at,
        "repository": {"name": repo.split("/")[-1], "full_name": repo},
        "dependency": {"package": {"name": pkg, "ecosystem": eco}},
        "security_advisory": {
            "ghsa_id": ghsa,
            "cve_id": None,
            "severity": severity,
            "summary": f"{pkg} vuln",
            "cvss": {"score": cvss},
        },
        "security_vulnerability": {
            "package": {"name": pkg, "ecosystem": eco},
            "vulnerable_version_range": "<4.17.21",
            "first_patched_version": {"identifier": patched} if patched else None,
        },
    }


MOCK_FINDINGS = [
    _make_finding(pkg="lodash", eco="npm", severity="critical", cvss=9.5, repo="org/repo-a", ghsa="GHSA-1"),
    _make_finding(pkg="express", eco="npm", severity="high", cvss=7.0, repo="org/repo-a", ghsa="GHSA-2"),
    _make_finding(pkg="django", eco="pip", severity="medium", cvss=5.0, repo="org/repo-b", patched=None, ghsa="GHSA-3"),
    _make_finding(pkg="flask", eco="pip", severity="low", cvss=2.0, repo="other/repo-c", state="fixed", fixed_at="2026-02-01T00:00:00Z", ghsa="GHSA-4"),
]

CTX = {
    "user_id": "u1",
    "role": "admin",
    "orgs": ["org"],
    "tier": "pro",
    "request": None,
    "_cache": {},
}


def _call(**kwargs):
    """Helper: call dependencies_findings with MOCK_FINDINGS patched in."""
    defaults = dict(org="org", page=1, per_page=25, info_context=CTX)
    defaults.update(kwargs)
    with patch("src.graphql.dependencies_resolvers._load_scoped_findings", return_value=list(MOCK_FINDINGS)):
        return dependencies_findings(**defaults)


# ---------------------------------------------------------------------------
# Ecosystem filter
# ---------------------------------------------------------------------------

def test_ecosystem_npm_only():
    result = _call(ecosystem=["npm"])
    names = [i.package_name for i in result.items]
    assert "lodash" in names
    assert "express" in names
    assert "django" not in names
    assert "flask" not in names
    assert result.total_count == 2


def test_ecosystem_pip_only():
    result = _call(ecosystem=["pip"])
    names = [i.package_name for i in result.items]
    assert "django" in names
    assert "flask" in names
    assert "lodash" not in names
    assert result.total_count == 2


def test_ecosystem_multiple():
    result = _call(ecosystem=["npm", "pip"])
    assert result.total_count == 4


def test_ecosystem_none_returns_all():
    result = _call(ecosystem=None)
    assert result.total_count == 4


def test_ecosystem_unknown_returns_empty():
    result = _call(ecosystem=["cargo"])
    assert result.total_count == 0


# ---------------------------------------------------------------------------
# Repository filter
# ---------------------------------------------------------------------------

def test_repository_full_name():
    result = _call(repository="org/repo-a")
    assert result.total_count == 2
    for item in result.items:
        assert item.repo_full_name == "org/repo-a"


def test_repository_short_name():
    result = _call(repository="repo-b")
    assert result.total_count == 1
    assert result.items[0].package_name == "django"


def test_repository_no_match():
    result = _call(repository="nonexistent/repo")
    assert result.total_count == 0


# ---------------------------------------------------------------------------
# Organization filter
# ---------------------------------------------------------------------------

def test_organization_filter():
    result = _call(organization="org")
    assert result.total_count == 3
    for item in result.items:
        assert item.repo_full_name.startswith("org/")


def test_organization_other():
    result = _call(organization="other")
    assert result.total_count == 1
    assert result.items[0].package_name == "flask"


def test_organization_no_match():
    result = _call(organization="unknown")
    assert result.total_count == 0


# ---------------------------------------------------------------------------
# fix_availability filter
# ---------------------------------------------------------------------------

def test_fix_availability_has_fix():
    result = _call(fix_availability="has_fix")
    # lodash, express, flask have patched versions; django does not
    names = [i.package_name for i in result.items]
    assert "lodash" in names
    assert "express" in names
    assert "flask" in names
    assert "django" not in names
    assert result.total_count == 3


def test_fix_availability_no_fix():
    result = _call(fix_availability="no_fix")
    assert result.total_count == 1
    assert result.items[0].package_name == "django"


def test_fix_availability_none_returns_all():
    result = _call(fix_availability=None)
    assert result.total_count == 4


def test_fix_availability_unknown_value_returns_all():
    # Unknown value should not filter anything
    result = _call(fix_availability="maybe")
    assert result.total_count == 4


# ---------------------------------------------------------------------------
# cvss_range filter
# ---------------------------------------------------------------------------

def test_cvss_range_critical():
    result = _call(cvss_range="9.0+")
    assert result.total_count == 1
    assert result.items[0].package_name == "lodash"


def test_cvss_range_high():
    result = _call(cvss_range="7.0-8.9")
    assert result.total_count == 1
    assert result.items[0].package_name == "express"


def test_cvss_range_medium():
    result = _call(cvss_range="4.0-6.9")
    assert result.total_count == 1
    assert result.items[0].package_name == "django"


def test_cvss_range_low():
    result = _call(cvss_range="0.1-3.9")
    assert result.total_count == 1
    assert result.items[0].package_name == "flask"


def test_cvss_range_unknown_returns_all():
    result = _call(cvss_range="invalid")
    assert result.total_count == 4


def test_cvss_range_en_dash_normalized():
    # en-dash variant of "7.0-8.9"
    result = _call(cvss_range="7.0\u20138.9")
    assert result.total_count == 1
    assert result.items[0].package_name == "express"


# ---------------------------------------------------------------------------
# search filter
# ---------------------------------------------------------------------------

def test_search_by_package_name():
    result = _call(search="lodash")
    assert result.total_count == 1
    assert result.items[0].package_name == "lodash"


def test_search_by_repo_name():
    result = _call(search="repo-b")
    assert result.total_count == 1
    assert result.items[0].package_name == "django"


def test_search_by_ghsa():
    result = _call(search="ghsa-3")
    assert result.total_count == 1
    assert result.items[0].package_name == "django"


def test_search_case_insensitive():
    result = _call(search="LODASH")
    assert result.total_count == 1


def test_search_no_match():
    result = _call(search="zzznotfound")
    assert result.total_count == 0


# ---------------------------------------------------------------------------
# package_search filter
# ---------------------------------------------------------------------------

def test_package_search_partial():
    result = _call(package_search="lo")
    assert result.total_count == 1
    assert result.items[0].package_name == "lodash"


def test_package_search_case_insensitive():
    result = _call(package_search="EXPRESS")
    assert result.total_count == 1
    assert result.items[0].package_name == "express"


def test_package_search_no_match():
    result = _call(package_search="requests")
    assert result.total_count == 0


# ---------------------------------------------------------------------------
# Combined filters
# ---------------------------------------------------------------------------

def test_combined_ecosystem_and_severity():
    result = _call(ecosystem=["npm"], severity="critical")
    assert result.total_count == 1
    assert result.items[0].package_name == "lodash"


def test_combined_organization_and_fix_availability():
    result = _call(organization="org", fix_availability="no_fix")
    assert result.total_count == 1
    assert result.items[0].package_name == "django"


def test_combined_state_and_ecosystem():
    result = _call(state="fixed", ecosystem=["pip"])
    assert result.total_count == 1
    assert result.items[0].package_name == "flask"


def test_combined_cvss_and_ecosystem():
    result = _call(cvss_range="9.0+", ecosystem=["npm"])
    assert result.total_count == 1
    assert result.items[0].package_name == "lodash"


# ---------------------------------------------------------------------------
# ecosystem field on DependenciesFinding
# ---------------------------------------------------------------------------

def test_ecosystem_field_populated():
    result = _call()
    ecosystems = {i.package_name: i.ecosystem for i in result.items}
    assert ecosystems["lodash"] == "npm"
    assert ecosystems["express"] == "npm"
    assert ecosystems["django"] == "pip"
    assert ecosystems["flask"] == "pip"


# ---------------------------------------------------------------------------
# new_since_last_scan filter
# ---------------------------------------------------------------------------

def test_new_since_last_scan_filters_old():
    # Only findings from 2026-02 onward
    result = _call(new_since_last_scan=True, last_scan_date="2026-02-01T00:00:00Z")
    # flask has created_at 2026-01-15, all others too; none >= 2026-02-01
    assert result.total_count == 0


def test_new_since_last_scan_all_pass():
    result = _call(new_since_last_scan=True, last_scan_date="2025-01-01T00:00:00Z")
    assert result.total_count == 4


def test_new_since_last_scan_false_does_not_filter():
    result = _call(new_since_last_scan=False, last_scan_date="2026-02-01T00:00:00Z")
    assert result.total_count == 4

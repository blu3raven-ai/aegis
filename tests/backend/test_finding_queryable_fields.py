"""Unit coverage for the queryable-field extractor.

These five values become the typed columns findings are filtered/searched on,
so a wrong key precedence or a leaked empty string silently mis-populates the
index across every finding. Pin the per-field fallback chains and the
truthy-string-only rule.
"""
from __future__ import annotations

import pytest

from src.shared.finding_queryable_fields import extract_queryable_fields

_EMPTY = {
    "cve_id": None,
    "file_path": None,
    "title": None,
    "rule_name": None,
    "package_name": None,
    "package_version": None,
}


@pytest.mark.parametrize("detail", [None, {}])
def test_empty_or_none_returns_all_null_shape(detail):
    assert extract_queryable_fields(detail) == _EMPTY


def test_extracts_primary_camelcase_keys():
    out = extract_queryable_fields(
        {
            "cveId": "CVE-2024-1",
            "filePath": "app/main.py",
            "title": "SQL injection",
            "ruleName": "B608",
            "packageName": "left-pad",
            "packageVersion": "1.3.0",
        }
    )
    assert out == {
        "cve_id": "CVE-2024-1",
        "file_path": "app/main.py",
        "title": "SQL injection",
        "rule_name": "B608",
        "package_name": "left-pad",
        "package_version": "1.3.0",
    }


def test_package_version_falls_back_to_current_version():
    # SCA/container findings carry the matched version as currentVersion; the
    # column derives from it when no explicit packageVersion is present.
    assert (
        extract_queryable_fields({"packageName": "log4j", "currentVersion": "2.14.1"})["package_version"]
        == "2.14.1"
    )
    assert (
        extract_queryable_fields({"package_name": "log4j", "current_version": "2.14.1"})["package_version"]
        == "2.14.1"
    )
    # packageVersion wins when both are present.
    assert (
        extract_queryable_fields({"packageVersion": "3.0.0", "currentVersion": "2.0.0"})["package_version"]
        == "3.0.0"
    )


def test_extracts_snake_case_fallbacks():
    out = extract_queryable_fields(
        {"cve_id": "CVE-2024-2", "file_path": "x.tf", "rule_name": "r1", "package_name": "p1"}
    )
    assert out["cve_id"] == "CVE-2024-2"
    assert out["file_path"] == "x.tf"
    assert out["rule_name"] == "r1"
    assert out["package_name"] == "p1"


def test_camelcase_wins_over_snakecase_when_both_present():
    # First key in the chain wins; camelCase precedes snake_case.
    out = extract_queryable_fields({"cveId": "CVE-NEW", "cve_id": "CVE-OLD", "cve": "CVE-LEGACY"})
    assert out["cve_id"] == "CVE-NEW"


def test_cve_third_fallback_key():
    assert extract_queryable_fields({"cve": "CVE-2024-3"})["cve_id"] == "CVE-2024-3"


@pytest.mark.parametrize("key", ["filePath", "file_path", "path", "manifestPath"])
def test_file_path_accepts_each_key_in_its_chain(key):
    assert extract_queryable_fields({key: "some/where"})["file_path"] == "some/where"


def test_file_path_precedence_order():
    out = extract_queryable_fields(
        {"filePath": "a", "file_path": "b", "path": "c", "manifestPath": "d"}
    )
    assert out["file_path"] == "a"
    # Drop the winner → next in chain takes over.
    assert extract_queryable_fields({"path": "c", "manifestPath": "d"})["file_path"] == "c"


def test_empty_string_is_treated_as_missing():
    # An empty string must not occupy the column — it should fall through.
    out = extract_queryable_fields({"cveId": "", "cve_id": "CVE-REAL"})
    assert out["cve_id"] == "CVE-REAL"
    # And an all-empty field yields None, not "".
    assert extract_queryable_fields({"title": ""})["title"] is None


def test_non_string_values_are_ignored():
    out = extract_queryable_fields(
        {"cveId": 123, "title": ["nope"], "ruleName": {"x": 1}, "packageName": None}
    )
    assert out["cve_id"] is None
    assert out["title"] is None
    assert out["rule_name"] is None
    assert out["package_name"] is None


def test_unrelated_keys_are_ignored():
    out = extract_queryable_fields({"severity": "high", "foo": "bar"})
    assert out == _EMPTY

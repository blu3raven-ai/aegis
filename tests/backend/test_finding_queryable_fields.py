"""Tests for the queryable-fields extractor."""
from __future__ import annotations

from src.shared.finding_queryable_fields import extract_queryable_fields


def test_empty_dict():
    """Empty dict returns 5-key dict with all values None."""
    result = extract_queryable_fields({})
    assert result == {
        "cve_id": None,
        "file_path": None,
        "title": None,
        "rule_name": None,
        "package_name": None,
    }


def test_none_input():
    """None input returns 5-key dict with all values None."""
    result = extract_queryable_fields(None)
    assert result == {
        "cve_id": None,
        "file_path": None,
        "title": None,
        "rule_name": None,
        "package_name": None,
    }


def test_code_scanning_fixture():
    """Code scanning detail extracts filePath and ruleName."""
    detail = {
        "ruleName": "sql-injection",
        "filePath": "app/db.py",
        "cwe": "CWE-89",
        "message": "Potential SQL injection",
        "language": "python",
    }
    result = extract_queryable_fields(detail)
    assert result == {
        "cve_id": None,
        "file_path": "app/db.py",
        "title": None,
        "rule_name": "sql-injection",
        "package_name": None,
    }


def test_dependencies_fixture():
    """Dependencies detail extracts cveId, packageName, and manifestPath."""
    detail = {
        "cveId": "CVE-2024-1234",
        "packageName": "requests",
        "manifestPath": "requirements.txt",
        "cvssScore": 7.5,
        "vulnerableVersionRange": "<2.0",
    }
    result = extract_queryable_fields(detail)
    assert result == {
        "cve_id": "CVE-2024-1234",
        "file_path": "requirements.txt",
        "title": None,
        "rule_name": None,
        "package_name": "requests",
    }


def test_secrets_fixture():
    """Secrets detail extracts filePath only."""
    detail = {
        "detector": "aws_key",
        "filePath": "app/config.py",
        "line": 42,
        "fingerprint": "abc123",
        "commit": "abc1234567890",
    }
    result = extract_queryable_fields(detail)
    assert result == {
        "cve_id": None,
        "file_path": "app/config.py",
        "title": None,
        "rule_name": None,
        "package_name": None,
    }


def test_container_scanning_fixture():
    """Container scanning detail extracts cveId and packageName."""
    detail = {
        "cveId": "CVE-2024-9999",
        "packageName": "openssl",
        "imageName": "alpine",
        "imageTag": "3.18",
        "imageDigest": "sha256:abc123",
    }
    result = extract_queryable_fields(detail)
    assert result == {
        "cve_id": "CVE-2024-9999",
        "file_path": None,
        "title": None,
        "rule_name": None,
        "package_name": "openssl",
    }


def test_cve_id_fallback_ordering():
    """cveId wins over cve_id and cve; cve_id wins over cve."""
    # Test cveId wins
    result = extract_queryable_fields({"cveId": "A", "cve_id": "B", "cve": "C"})
    assert result["cve_id"] == "A"

    # Test cve_id wins when cveId absent
    result = extract_queryable_fields({"cve_id": "B", "cve": "C"})
    assert result["cve_id"] == "B"

    # Test cve is fallback
    result = extract_queryable_fields({"cve": "C"})
    assert result["cve_id"] == "C"


def test_file_path_fallback_ordering():
    """filePath wins; fallback order: file_path, path, manifestPath."""
    # Test filePath wins
    result = extract_queryable_fields(
        {"filePath": "A", "file_path": "B", "path": "C", "manifestPath": "D"}
    )
    assert result["file_path"] == "A"

    # Test file_path wins when filePath absent
    result = extract_queryable_fields({"file_path": "B", "path": "C", "manifestPath": "D"})
    assert result["file_path"] == "B"

    # Test path wins when filePath and file_path absent
    result = extract_queryable_fields({"path": "C", "manifestPath": "D"})
    assert result["file_path"] == "C"

    # Test manifestPath is fallback
    result = extract_queryable_fields({"manifestPath": "D"})
    assert result["file_path"] == "D"


def test_legacy_snake_case_data():
    """Legacy snake_case data (pre-promotion) is correctly extracted."""
    detail = {"cve_id": "CVE-OLD", "file_path": "old.py", "rule_name": "old_rule"}
    result = extract_queryable_fields(detail)
    assert result == {
        "cve_id": "CVE-OLD",
        "file_path": "old.py",
        "title": None,
        "rule_name": "old_rule",
        "package_name": None,
    }


def test_non_string_values_ignored():
    """Non-string values (int, list, dict, None, empty string) are treated as missing."""
    detail = {
        "cveId": 12345,  # int
        "filePath": None,  # None
        "title": ["list", "of", "things"],  # list
        "ruleName": {"nested": "dict"},  # dict
        "packageName": "",  # empty string
    }
    result = extract_queryable_fields(detail)
    assert result == {
        "cve_id": None,
        "file_path": None,
        "title": None,
        "rule_name": None,
        "package_name": None,
    }


def test_mixed_strings_and_non_strings():
    """Non-string values are skipped; fallback chain continues to next key."""
    detail = {
        "cveId": 12345,  # int, skipped
        "cve_id": "CVE-2024-1234",  # string, taken
        "filePath": None,  # None, skipped
        "file_path": "path.py",  # string, taken
    }
    result = extract_queryable_fields(detail)
    assert result["cve_id"] == "CVE-2024-1234"
    assert result["file_path"] == "path.py"


def test_no_mutation_of_input():
    """The extractor does not mutate the input dict."""
    original = {
        "cveId": "CVE-2024-1234",
        "filePath": "app.py",
        "title": "Test",
        "ruleName": "rule1",
        "packageName": "pkg",
    }
    original_copy = dict(original)
    extract_queryable_fields(original)
    assert original == original_copy


def test_extractor_reads_only_lean_keys():
    """Guard against silent changes to which extractor keys are lean vs fat.

    The extractor runs BEFORE split_detail at write time, so it sees the full
    detail dict regardless of lean/fat. This guard documents the current
    split so a future PR that moves manifestPath to fat (the last lean
    extractor key) gets a loud failure to update the test.
    """
    from src.shared.finding_detail_blob import LEAN_KEYS

    all_lean = set().union(*LEAN_KEYS.values())
    primary_extractor_keys = {
        "cveId",
        "filePath",
        "title",
        "ruleName",
        "packageName",
        "manifestPath",
    }
    expected_fat = {"cveId", "filePath", "title", "ruleName", "packageName"}
    actual_fat = primary_extractor_keys - all_lean
    assert (
        actual_fat == expected_fat
    ), f"Extractor fat keys changed from {expected_fat} to {actual_fat}. If lean, add to LEAN_KEYS. If fat, document why the extractor depends on MinIO."

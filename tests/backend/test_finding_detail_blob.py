"""Tests for the finding detail blob splitter/hydrator module."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.shared.finding_detail_blob import (
    LEAN_KEYS,
    build_blob_key,
    delete_detail_blob,
    finding_detail_blob_read_misses_total,
    finding_detail_blob_reads_total,
    finding_detail_blob_writes_total,
    hydrate_detail,
    put_detail_blob,
    split_detail,
)


# ---------------------------------------------------------------------------
# LEAN_KEYS snapshot — accidental additions, removals, or renames fail loudly
# ---------------------------------------------------------------------------

def test_lean_keys_code_scanning_snapshot():
    assert LEAN_KEYS["code_scanning"] == {
        "ruleId",
        "startLine",
        "endLine",
        "message",
        "category",
        "cwe",
        "owasp",
        "confidence",
        "language",
        "fileClass",
        "ruleIds",
    }


def test_lean_keys_dependencies_snapshot():
    assert LEAN_KEYS["dependencies"] == {
        "ecosystem",
        "advisoryId",
        "vulnerableVersionRange",
        "patchedVersion",
        "manifestPath",
        "currentVersion",
        "source",
        "scanner",
        "matchedBy",
        "cvssScore",
        "advisoryUrl",
    }


def test_lean_keys_secrets_snapshot():
    assert LEAN_KEYS["secrets"] == {
        "organization",
        "secretIdentity",
        "fingerprint",
        "detector",
        "source",
        "repository",
        "line",
        "commit",
        "detectedAt",
    }


def test_lean_keys_container_scanning_snapshot():
    assert LEAN_KEYS["container_scanning"] == {
        "ecosystem",
        "advisoryId",
        "vulnerableVersionRange",
        "patchedVersion",
        "manifestPath",
        "imageName",
        "imageTag",
        "imageDigest",
        "currentVersion",
        "source",
        "scanner",
        "matchedBy",
        "fixState",
        "cvssScore",
        "advisoryUrl",
    }


# ---------------------------------------------------------------------------
# split_detail — per-tool partitioning behaviour
# ---------------------------------------------------------------------------

def test_split_detail_code_scanning_lean_keys_stay_lean():
    detail = {
        "ruleId": "java/sql-injection",
        "ruleName": "SQL Injection",
        "filePath": "src/main.java",
        "startLine": 42,
        "endLine": 45,
        "message": "Unsafe query",
        "category": "security",
        "cwe": ["CWE-89"],
        "owasp": ["A03"],
        "confidence": "high",
        "language": "java",
        "fileClass": "source",
        "ruleIds": ["java/sql-injection"],
        # fat keys
        "snippet": "String q = ...",
        "dataflowTrace": {"nodes": []},
        "fixSuggestion": "Use prepared statements",
        "code_flows": [],
    }
    lean, fat = split_detail("code_scanning", detail)

    # all LEAN_KEYS present in lean
    for key in LEAN_KEYS["code_scanning"]:
        if key in detail:
            assert key in lean, f"{key!r} should be lean"

    # fat keys are NOT in lean
    for key in ("snippet", "dataflowTrace", "fixSuggestion", "code_flows"):
        assert key not in lean
        assert key in fat


def test_split_detail_dependencies_lean_keys_stay_lean():
    detail = {
        "packageName": "lodash",
        "ecosystem": "npm",
        "advisoryId": "GHSA-xxxx",
        "cveId": "CVE-2021-1234",
        "vulnerableVersionRange": "< 4.17.21",
        "patchedVersion": "4.17.21",
        "manifestPath": "package.json",
        "currentVersion": "4.17.0",
        "source": "git",
        "scanner": "grype",
        "matchedBy": [],
        "cvssScore": 9.8,
        "advisoryUrl": "https://example.com/advisory",
        # fat keys
        "summary": "Prototype pollution",
        "description": "A long description...",
        "references": [{"url": "https://example.com"}],
        "cvssVector": "CVSS:3.1/AV:N/AC:L",
        "publishedAt": "2021-01-01",
        "advisoryUpdatedAt": "2021-06-01",
        "manifestSnippet": "  lodash: ^4.0.0",
        "manifestMatchLine": 12,
    }
    lean, fat = split_detail("dependencies", detail)

    for key in LEAN_KEYS["dependencies"]:
        if key in detail:
            assert key in lean

    for key in ("summary", "description", "references", "cvssVector", "publishedAt", "advisoryUpdatedAt", "manifestSnippet", "manifestMatchLine"):
        assert key not in lean
        assert key in fat


def test_split_detail_unknown_keys_go_to_fat():
    """Any key not in the allowlist ends up in fat, never lean."""
    detail = {
        "ruleId": "r1",
        "unknownBigField": {"trace": [1, 2, 3]},
        "anotherFat": "value",
    }
    lean, fat = split_detail("code_scanning", detail)
    assert "ruleId" in lean
    assert "unknownBigField" in fat
    assert "anotherFat" in fat
    assert "unknownBigField" not in lean
    assert "anotherFat" not in lean


def test_split_detail_does_not_mutate_input():
    original = {"ruleId": "r1", "snippet": "code", "extra": "data"}
    original_copy = dict(original)
    split_detail("code_scanning", original)
    assert original == original_copy


def test_split_detail_empty_detail():
    lean, fat = split_detail("code_scanning", {})
    assert lean == {}
    assert fat == {}


def test_split_detail_unknown_tool_keeps_everything_lean(caplog):
    """Unknown tool: all keys stay lean, fat is empty, warning is emitted."""
    import logging
    detail = {"foo": 1, "bar": "baz"}
    with caplog.at_level(logging.WARNING, logger="src.shared.finding_detail_blob"):
        lean, fat = split_detail("brand_new_tool", detail)

    assert lean == {"foo": 1, "bar": "baz"}
    assert fat == {}
    assert any("brand_new_tool" in msg for msg in caplog.messages)


# ---------------------------------------------------------------------------
# build_blob_key
# ---------------------------------------------------------------------------

def test_build_blob_key():
    assert build_blob_key(42) == "findings/42/detail.json"
    assert build_blob_key(1) == "findings/1/detail.json"


# ---------------------------------------------------------------------------
# put_detail_blob — empty fat → no write, returns None
# ---------------------------------------------------------------------------

def test_put_detail_blob_empty_returns_none():
    result = put_detail_blob(999, {})
    assert result is None


# ---------------------------------------------------------------------------
# Real MinIO round-trip: split → put → hydrate equals the original detail
# ---------------------------------------------------------------------------

def test_round_trip_split_put_hydrate(s3_endpoint):
    """Full round-trip using the testcontainers MinIO instance."""
    original = {
        "ruleId": "java/sqli",
        "ruleName": "SQL Injection",
        "filePath": "src/App.java",
        "startLine": 10,
        "endLine": 12,
        "message": "Unsafe query",
        "category": "security",
        "cwe": ["CWE-89"],
        "owasp": [],
        "confidence": "high",
        "language": "java",
        "fileClass": "source",
        "ruleIds": ["java/sqli"],
        # fat fields
        "snippet": "String q = input;",
        "dataflowTrace": {"nodes": [{"file": "App.java", "line": 5}]},
        "fixSuggestion": "Use PreparedStatement",
    }

    finding_id = 10001
    lean, fat = split_detail("code_scanning", original)
    key = put_detail_blob(finding_id, fat)
    assert key == build_blob_key(finding_id)

    # Simulate a Finding row with lean detail and the blob key
    row = SimpleNamespace(detail=lean, detail_blob_key=key, id=finding_id)
    hydrated = hydrate_detail(row)

    assert hydrated == original


def test_put_detail_blob_returns_key_and_data_is_json(s3_endpoint):
    """put_detail_blob stores valid JSON in MinIO."""
    from src.shared.object_store import download_json

    fat = {"snippet": "code here", "dataflowTrace": {"nodes": []}}
    key = put_detail_blob(20001, fat)
    assert key == "findings/20001/detail.json"

    downloaded = download_json(key)
    assert downloaded == fat


# ---------------------------------------------------------------------------
# Hydration with missing blob — returns lean, logs warning, does not raise
# ---------------------------------------------------------------------------

def test_hydrate_detail_missing_blob_returns_lean_no_raise(caplog, s3_endpoint):
    import logging
    lean = {"ruleId": "r1", "filePath": "foo.java"}
    row = SimpleNamespace(detail=lean, detail_blob_key="findings/99999/detail.json", id=99999)

    with caplog.at_level(logging.WARNING, logger="src.shared.finding_detail_blob"):
        result = hydrate_detail(row)

    assert result == lean
    assert any("99999" in msg or "missing" in msg.lower() for msg in caplog.messages)


def test_hydrate_detail_no_blob_key_returns_lean():
    lean = {"ruleId": "r1"}
    row = SimpleNamespace(detail=lean, detail_blob_key=None, id=1)
    result = hydrate_detail(row)
    assert result == lean


# ---------------------------------------------------------------------------
# Hydration cache: second call must not trigger another S3 GET
# ---------------------------------------------------------------------------

def test_hydrate_detail_cache_prevents_second_s3_get():
    """hydrate_detail must hit S3 only once per row instance."""
    lean = {"ruleId": "cached-rule"}
    fat = {"snippet": "big code block"}
    merged = {**lean, **fat}
    blob_key = "findings/30001/detail.json"

    row = SimpleNamespace(detail=lean, detail_blob_key=blob_key, id=30001)

    mock_client = MagicMock()
    # Simulate a successful download
    with patch("src.shared.finding_detail_blob.download_json", return_value=fat) as mock_dl:
        result1 = hydrate_detail(row)
        result2 = hydrate_detail(row)

    assert result1 == merged
    assert result2 == merged
    # download_json must have been called exactly once
    assert mock_dl.call_count == 1


# ---------------------------------------------------------------------------
# fat wins on key conflict during hydration
# ---------------------------------------------------------------------------

def test_hydrate_detail_fat_overwrites_lean_on_conflict():
    """If lean and fat share a key (shouldn't happen in practice), fat wins."""
    lean = {"ruleId": "old-rule", "shared_key": "lean_value"}
    fat = {"shared_key": "fat_value", "snippet": "code"}
    blob_key = "findings/40001/detail.json"

    row = SimpleNamespace(detail=lean, detail_blob_key=blob_key, id=40001)

    with patch("src.shared.finding_detail_blob.download_json", return_value=fat):
        result = hydrate_detail(row)

    assert result["shared_key"] == "fat_value"
    assert result["ruleId"] == "old-rule"
    assert result["snippet"] == "code"


# ---------------------------------------------------------------------------
# Prometheus counters — writes, reads, and misses
# ---------------------------------------------------------------------------

def test_write_counter_increments_on_real_put(s3_endpoint):
    """put_detail_blob increments writes_total on successful upload."""
    # Snapshot before
    before = finding_detail_blob_writes_total._value.get()

    # Put a blob
    fat = {"snippet": "code here", "dataflowTrace": {"nodes": []}}
    put_detail_blob(50001, fat)

    # Snapshot after
    after = finding_detail_blob_writes_total._value.get()
    assert after == before + 1, f"Expected writes_total to increment by 1, got {after} vs {before}"


def test_write_counter_does_not_increment_on_empty_fat():
    """put_detail_blob does NOT increment writes_total when fat is empty."""
    before = finding_detail_blob_writes_total._value.get()

    # Put empty fat
    result = put_detail_blob(50002, {})

    after = finding_detail_blob_writes_total._value.get()
    assert result is None, "Empty fat should return None"
    assert after == before, f"Counter should not change on empty fat: {after} vs {before}"


def test_read_counter_increments_on_minio_hit(s3_endpoint):
    """hydrate_detail increments reads_total when blob exists, not misses_total."""
    before_reads = finding_detail_blob_reads_total._value.get()
    before_misses = finding_detail_blob_read_misses_total._value.get()

    # Put a blob
    fat = {"snippet": "code", "dataflowTrace": {}}
    key = put_detail_blob(50003, fat)

    # Create a fresh row (new instance so cache doesn't apply)
    lean = {"ruleId": "test-rule"}
    row = SimpleNamespace(detail=lean, detail_blob_key=key, id=50003)

    # Hydrate — should hit MinIO
    result = hydrate_detail(row)

    after_reads = finding_detail_blob_reads_total._value.get()
    after_misses = finding_detail_blob_read_misses_total._value.get()

    assert result == {**lean, **fat}, "Hydration should merge lean and fat"
    assert after_reads == before_reads + 1, f"reads_total should increment: {after_reads} vs {before_reads}"
    assert after_misses == before_misses, f"read_misses_total should NOT increment on hit: {after_misses} vs {before_misses}"


def test_read_miss_counter_increments_when_blob_missing(s3_endpoint):
    """hydrate_detail increments both reads_total AND read_misses_total when blob is gone."""
    before_reads = finding_detail_blob_reads_total._value.get()
    before_misses = finding_detail_blob_read_misses_total._value.get()

    # Put a blob, then delete it
    fat = {"snippet": "code"}
    key = put_detail_blob(50004, fat)
    delete_detail_blob(key)

    # Create a row pointing to the deleted blob
    lean = {"ruleId": "test-rule"}
    row = SimpleNamespace(detail=lean, detail_blob_key=key, id=50004)

    # Hydrate — should attempt MinIO GET, get None, increment both counters
    result = hydrate_detail(row)

    after_reads = finding_detail_blob_reads_total._value.get()
    after_misses = finding_detail_blob_read_misses_total._value.get()

    assert result == lean, "Missing blob should return lean only"
    assert after_reads == before_reads + 1, f"reads_total should increment: {after_reads} vs {before_reads}"
    assert after_misses == before_misses + 1, f"read_misses_total should increment: {after_misses} vs {before_misses}"


def test_cache_hit_short_circuit_does_not_touch_counters():
    """hydrate_detail on cached row does NOT increment read counters."""
    before_reads = finding_detail_blob_reads_total._value.get()
    before_misses = finding_detail_blob_read_misses_total._value.get()

    # Create a row with a cached detail
    lean = {"ruleId": "test-rule"}
    row = SimpleNamespace(detail=lean, detail_blob_key="findings/50005/detail.json", id=50005)
    cached_detail = {**lean, "extra": "cached"}
    setattr(row, "_hydrated_detail", cached_detail)

    # Call hydrate twice — should only use cache
    result1 = hydrate_detail(row)
    result2 = hydrate_detail(row)

    after_reads = finding_detail_blob_reads_total._value.get()
    after_misses = finding_detail_blob_read_misses_total._value.get()

    assert result1 == cached_detail, "First call should return cached detail"
    assert result2 == cached_detail, "Second call should return cached detail"
    assert after_reads == before_reads, f"reads_total should NOT change on cache hits: {after_reads} vs {before_reads}"
    assert after_misses == before_misses, f"read_misses_total should NOT change on cache hits: {after_misses} vs {before_misses}"

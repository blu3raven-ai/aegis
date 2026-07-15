"""Unit tests for the finding detail blob splitter/hydrator module.

These cover the pure split/partition contract (no MinIO round-trip): what stays
lean, what moves to fat, input-immutability, unknown-tool handling, key building,
and the read/write counter short-circuits. The real-MinIO round-trip and
encryption behaviour is covered by test_finding_detail_blob_encryption.py.
"""
from __future__ import annotations

from types import SimpleNamespace

from src.shared.finding_detail_blob import (
    LEAN_KEYS,
    build_blob_key,
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
# Hydration with no blob key — returns lean, does not touch S3
# ---------------------------------------------------------------------------

def test_hydrate_detail_no_blob_key_returns_lean():
    lean = {"ruleId": "r1"}
    row = SimpleNamespace(detail=lean, detail_blob_key=None, id=1)
    result = hydrate_detail(row)
    assert result == lean


# ---------------------------------------------------------------------------
# Prometheus counters — writes and read short-circuit
# ---------------------------------------------------------------------------

def test_write_counter_does_not_increment_on_empty_fat():
    """put_detail_blob does NOT increment writes_total when fat is empty."""
    before = finding_detail_blob_writes_total._value.get()

    # Put empty fat
    result = put_detail_blob(50002, {})

    after = finding_detail_blob_writes_total._value.get()
    assert result is None, "Empty fat should return None"
    assert after == before, f"Counter should not change on empty fat: {after} vs {before}"


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

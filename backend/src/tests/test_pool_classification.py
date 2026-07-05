"""Tests for classificationHistory append behaviour in merge_run_into_pool.

These tests mock run_db to avoid needing a live PostgreSQL connection.
"""
from __future__ import annotations


def _scanner_entry(run_id: str, scan_depth: str = "light", value: str = "uncertain") -> dict:
    return {
        "value": value,
        "source": "scanner",
        "scanDepth": scan_depth,
        "confidence": 0.9 if value == "confirmed" else 0.5,
        "runId": run_id,
        "scannedAt": "2026-04-27T00:00:00Z",
    }


def _ai_entry(run_id: str, value: str = "likely_real") -> dict:
    return {
        "value": value,
        "source": "ai",
        "scanDepth": "deep",
        "confidence": 0.8,
        "runId": run_id,
        "scannedAt": "2026-04-27T01:00:00Z",
    }


def _make_finding(fingerprint: str, history: list) -> dict:
    return {
        "fingerprint": fingerprint,
        "organization": "example-org",
        "repository": "repo-a",
        "detectedAt": "2026-04-27T00:00:00Z",
        "commit": "abc123",
        "classificationHistory": history,
    }


def test_entries_to_append_new_fingerprint():
    """First scan: all entries are appended (nothing to skip)."""
    from src.secrets.pool import _entries_to_append
    existing_history: list = []
    new_entries = [_scanner_entry("run-1")]
    result = _entries_to_append(existing_history, new_entries)
    assert result == new_entries


def test_entries_to_append_skips_duplicate_run_id():
    """Same runId is never appended twice."""
    from src.secrets.pool import _entries_to_append
    existing = [_scanner_entry("run-1")]
    new = [_scanner_entry("run-1")]  # Same runId
    assert _entries_to_append(existing, new) == []


def test_entries_to_append_allows_different_run_id():
    """Different runId from same scan depth is appended."""
    from src.secrets.pool import _entries_to_append
    existing = [_scanner_entry("run-1", "light")]
    new = [_scanner_entry("run-2", "light")]
    result = _entries_to_append(existing, new)
    assert len(result) == 1
    assert result[0]["runId"] == "run-2"


def test_entries_to_append_allows_ai_entry_after_scanner_entry():
    """Deep run with AI classification appends ai entry after existing scanner entry."""
    from src.secrets.pool import _entries_to_append
    existing = [_scanner_entry("run-1", "light")]
    new = [_ai_entry("run-2")]
    result = _entries_to_append(existing, new)
    assert len(result) == 1
    assert result[0]["source"] == "ai"
    assert result[0]["runId"] == "run-2"


def test_entries_to_append_empty_new_entries():
    from src.secrets.pool import _entries_to_append
    existing = [_scanner_entry("run-1")]
    assert _entries_to_append(existing, []) == []


def test_entries_to_append_both_empty():
    from src.secrets.pool import _entries_to_append
    assert _entries_to_append([], []) == []

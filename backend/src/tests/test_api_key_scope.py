"""Tests for scan:trigger scope checks on API keys."""
from __future__ import annotations

from src.auth.credentials.auth import require_scope_and_source


class _FakeKey:
    def __init__(self, scopes: list[str], allowed_source_ids: list[str] | None = None) -> None:
        self.scopes = scopes
        self.allowed_source_ids = allowed_source_ids


def test_scope_granted_when_scope_present_and_no_source_allowlist() -> None:
    key = _FakeKey(scopes=["scan:trigger"], allowed_source_ids=None)
    err = require_scope_and_source(key, scope="scan:trigger", source_id="any-source-id")
    assert err is None


def test_scope_denied_when_scope_missing() -> None:
    key = _FakeKey(scopes=["view_findings"], allowed_source_ids=None)
    err = require_scope_and_source(key, scope="scan:trigger", source_id="any-source-id")
    assert err == {"error": "missing_scope", "missing_scope": "scan:trigger"}


def test_source_denied_when_not_in_allowlist() -> None:
    key = _FakeKey(scopes=["scan:trigger"], allowed_source_ids=["src-a", "src-b"])
    err = require_scope_and_source(key, scope="scan:trigger", source_id="src-c")
    assert err == {"error": "source_not_in_scope", "source_id": "src-c"}


def test_source_allowed_when_in_allowlist() -> None:
    key = _FakeKey(scopes=["scan:trigger"], allowed_source_ids=["src-a", "src-b"])
    err = require_scope_and_source(key, scope="scan:trigger", source_id="src-a")
    assert err is None


def test_empty_allowlist_treated_as_unrestricted() -> None:
    # An empty list (different from None) is treated as "no allowlist set yet" → unrestricted.
    # This matches Postgres NULL semantics on the JSONB column.
    key = _FakeKey(scopes=["scan:trigger"], allowed_source_ids=[])
    err = require_scope_and_source(key, scope="scan:trigger", source_id="any-source")
    assert err is None

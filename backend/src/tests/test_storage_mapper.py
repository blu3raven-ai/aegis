"""Unit tests for storage mapper functions.

These tests run without a database — they test the pure dict-mapping logic in
_finding_to_dependencies_alert to guard against None values sneaking through
to non-nullable GraphQL fields.
"""
from __future__ import annotations
from unittest.mock import MagicMock
from datetime import datetime, timezone

from src.storage import _finding_to_dependencies_alert


def _make_finding(detail: dict) -> MagicMock:
    f = MagicMock()
    f.state = "open"
    f.severity = "high"
    f.review_status = None
    f.first_seen_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    f.fixed_at = None
    f.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    f.updated_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    f.repo = "acme-org/some-image"
    f.detail = detail
    return f


def test_null_advisory_url_becomes_empty_string():
    """advisoryUrl=null in DB must not produce None in html_url — Strawberry
    would fail to serialize None as non-nullable String and return data=null."""
    f = _make_finding({"advisoryUrl": None, "packageName": "torch", "ecosystem": "python"})
    result = _finding_to_dependencies_alert(f, None)
    html_url = result["security_advisory"]["html_url"]
    assert html_url == "", f"Expected empty string, got {html_url!r}"
    assert html_url is not None, "html_url must not be None — breaks GraphQL serialization"


def test_missing_advisory_url_becomes_empty_string():
    """advisoryUrl absent from detail must also default to empty string."""
    f = _make_finding({"packageName": "torch", "ecosystem": "python"})
    result = _finding_to_dependencies_alert(f, None)
    assert result["security_advisory"]["html_url"] == ""


def test_valid_advisory_url_is_preserved():
    """A real advisoryUrl must pass through unchanged."""
    url = "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
    f = _make_finding({"advisoryUrl": url})
    result = _finding_to_dependencies_alert(f, None)
    assert result["security_advisory"]["html_url"] == url

"""Tests for _finding_to_secret_dict review_status mapping."""
from __future__ import annotations

import types
from src.storage import _finding_to_secret_dict


def _make_finding(state: str = "open", review_status: str | None = None) -> object:
    """Minimal Finding stub — only the fields _finding_to_secret_dict reads."""
    f = types.SimpleNamespace()
    f.state = state
    f.review_status = review_status
    f.org = "acme"
    f.identity_key = "sha-aaa"
    f.severity = "high"
    f.detail = {
        "secretIdentity": "sha-aaa",
        "fingerprint": "fp-1",
        "detector": "generic-api-key",
        "source": "betterleaks",
        "locations": [],
        "classificationHistory": [],
        "organization": "acme",
        "repository": "repo-a",
        "filePath": "config.py",
        "line": 5,
        "commit": "abc",
        "detectedAt": "2026-05-01T00:00:00Z",
        "secretSnippet": "[redacted]",
        "aiReasoning": None,
        "raw": {},
    }
    return f


def test_review_status_new_when_column_is_none():
    f = _make_finding(state="open", review_status=None)
    result = _finding_to_secret_dict(f)
    assert result["reviewStatus"] == "new"


def test_review_status_confirmed_reads_from_column():
    f = _make_finding(state="open", review_status="confirmed")
    result = _finding_to_secret_dict(f)
    assert result["reviewStatus"] == "confirmed"


def test_review_status_action_taken_reads_from_column():
    f = _make_finding(state="dismissed", review_status="action_taken")
    result = _finding_to_secret_dict(f)
    assert result["reviewStatus"] == "action_taken"


def test_review_status_false_positive_reads_from_column():
    f = _make_finding(state="dismissed", review_status="false_positive")
    result = _finding_to_secret_dict(f)
    assert result["reviewStatus"] == "false_positive"


def test_review_status_not_inferred_from_dismissed_state():
    """state=dismissed alone must NOT automatically produce false_positive."""
    f = _make_finding(state="dismissed", review_status=None)
    result = _finding_to_secret_dict(f)
    assert result["reviewStatus"] == "new"


def test_review_status_not_inferred_from_fixed_state():
    """state=fixed alone must NOT automatically produce action_taken."""
    f = _make_finding(state="fixed", review_status=None)
    result = _finding_to_secret_dict(f)
    assert result["reviewStatus"] == "new"

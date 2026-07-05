"""Pure-unit tests for category action schema validation.

No DB or external services required — these exercise only the Pydantic models
and the ``validate_action_for_category`` dispatch function.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.rules.action_schemas import (
    AutoDismissAction,
    _RESERVED_CATEGORIES,
    _SUPPORTED_CATEGORIES,
    validate_action_for_category,
)


# ── AutoDismissAction field constraints ───────────────────────────────────────


def test_auto_dismiss_action_defaults():
    action = AutoDismissAction(reason="Low-signal noise rule")
    assert action.audit_note is None
    assert action.rate_alarm_pct == 50.0
    assert action.rate_alarm_window_minutes == 60


def test_auto_dismiss_action_full():
    action = AutoDismissAction(
        reason="Suppress informational bot findings",
        audit_note="Approved by security team in Q2 review",
        rate_alarm_pct=75.0,
        rate_alarm_window_minutes=120,
    )
    assert action.reason == "Suppress informational bot findings"
    assert action.audit_note == "Approved by security team in Q2 review"
    assert action.rate_alarm_pct == 75.0
    assert action.rate_alarm_window_minutes == 120


def test_auto_dismiss_reason_too_short():
    with pytest.raises(ValidationError):
        AutoDismissAction(reason="ab")


def test_auto_dismiss_reason_too_long():
    with pytest.raises(ValidationError):
        AutoDismissAction(reason="x" * 201)


def test_auto_dismiss_audit_note_too_long():
    with pytest.raises(ValidationError):
        AutoDismissAction(reason="Valid reason here", audit_note="x" * 501)


def test_auto_dismiss_rate_alarm_window_minimum_is_five():
    # ge=5: 4 must be rejected, 5 must be accepted
    with pytest.raises(ValidationError):
        AutoDismissAction(reason="Valid reason here", rate_alarm_window_minutes=4)

    action = AutoDismissAction(reason="Valid reason here", rate_alarm_window_minutes=5)
    assert action.rate_alarm_window_minutes == 5


def test_auto_dismiss_rate_alarm_pct_bounds():
    with pytest.raises(ValidationError):
        AutoDismissAction(reason="Valid reason here", rate_alarm_pct=0.9)

    with pytest.raises(ValidationError):
        AutoDismissAction(reason="Valid reason here", rate_alarm_pct=100.1)


def test_auto_dismiss_rate_alarm_window_upper_bound():
    # le=10080 (one week in minutes): 10080 must be accepted, 10081 rejected
    action = AutoDismissAction(reason="Valid reason here", rate_alarm_window_minutes=10080)
    assert action.rate_alarm_window_minutes == 10080

    with pytest.raises(ValidationError):
        AutoDismissAction(reason="Valid reason here", rate_alarm_window_minutes=10081)


# ── Category set membership ───────────────────────────────────────────────────


def test_auto_dismiss_is_supported():
    assert "auto_dismiss" in _SUPPORTED_CATEGORIES


def test_auto_dismiss_not_reserved():
    assert "auto_dismiss" not in _RESERVED_CATEGORIES


def test_data_retention_still_reserved():
    assert "data_retention" in _RESERVED_CATEGORIES
    assert "data_retention" not in _SUPPORTED_CATEGORIES


# ── validate_action_for_category dispatch ────────────────────────────────────


def test_validate_action_accepts_auto_dismiss():
    result = validate_action_for_category(
        "auto_dismiss",
        {"reason": "Suppress noisy scanner alerts"},
    )
    assert isinstance(result, AutoDismissAction)
    assert result.reason == "Suppress noisy scanner alerts"


def test_validate_action_rejects_reserved_category():
    with pytest.raises(ValueError, match="reserved for a future phase"):
        validate_action_for_category("data_retention", {"action": "archive", "after_days": 30})


def test_validate_action_rejects_unknown_category():
    with pytest.raises(ValueError, match="unknown rule category"):
        validate_action_for_category("nonexistent", {})


def test_validate_action_rejects_invalid_auto_dismiss_payload():
    with pytest.raises(ValidationError):
        validate_action_for_category("auto_dismiss", {"reason": "ab"})

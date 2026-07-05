"""Unit coverage for per-category rule-action validation.

`validate_action_for_category` is the boundary that rejects malformed rule
actions before they're persisted and later executed by the evaluators. The
bounds (SLA deadlines, retention floors, rate-alarm percentages) and the
discriminated unions are the contract; a gap here lets a bad rule through that
fails — or misbehaves — at evaluation time. pydantic's ValidationError is a
ValueError subclass, matching the function's documented "raises ValueError".
"""
from __future__ import annotations

import pytest

from src.rules.action_schemas import (
    AutoDismissAction,
    SlaAction,
    validate_action_for_category,
)


# ── category routing ─────────────────────────────────────────────────────────

def test_unknown_category_raises_value_error():
    with pytest.raises(ValueError, match="unknown rule category"):
        validate_action_for_category("bogus", {"reason": "x"})


def test_returns_the_category_model_type():
    out = validate_action_for_category("auto_dismiss", {"reason": "duplicate"})
    assert isinstance(out, AutoDismissAction)
    out2 = validate_action_for_category("sla", {"deadline_days": 30})
    assert isinstance(out2, SlaAction)


# ── sla ──────────────────────────────────────────────────────────────────────

def test_sla_minimal_valid():
    out = validate_action_for_category("sla", {"deadline_days": 30})
    assert out.deadline_days == 30
    assert out.escalations == []


def test_sla_with_escalations():
    out = validate_action_for_category(
        "sla",
        {"deadline_days": 14, "escalations": [{"at_hours": 24, "channel_id": 5}]},
    )
    assert out.escalations[0].at_hours == 24


@pytest.mark.parametrize("days", [0, 3651])
def test_sla_deadline_days_out_of_bounds(days):
    with pytest.raises(ValueError):
        validate_action_for_category("sla", {"deadline_days": days})


def test_sla_escalation_at_hours_must_be_positive():
    with pytest.raises(ValueError):
        validate_action_for_category(
            "sla", {"deadline_days": 10, "escalations": [{"at_hours": 0, "channel_id": 1}]}
        )


# ── scanner_coverage (discriminated) ─────────────────────────────────────────

def test_scanner_coverage_require_scanners_valid():
    out = validate_action_for_category(
        "scanner_coverage",
        {"type": "require_scanners", "required_scanners": ["code_scanning"]},
    )
    assert out.required_scanners == ["code_scanning"]


def test_scanner_coverage_require_scanners_needs_at_least_one():
    with pytest.raises(ValueError):
        validate_action_for_category(
            "scanner_coverage", {"type": "require_scanners", "required_scanners": []}
        )


def test_scanner_coverage_unknown_scanner_literal_rejected():
    with pytest.raises(ValueError):
        validate_action_for_category(
            "scanner_coverage",
            {"type": "require_scanners", "required_scanners": ["telepathy_scanning"]},
        )


def test_scanner_coverage_stale_alert_valid():
    out = validate_action_for_category(
        "scanner_coverage",
        {"type": "stale_alert", "stale_after_days": 7, "alert_channel_id": 3},
    )
    assert out.stale_after_days == 7
    assert out.auto_retrigger is False


def test_scanner_coverage_stale_alert_without_channel_is_valid():
    # Notify-channel delivery is a coming-soon leg, so a channel is optional:
    # the stale alert still opens a violation without one.
    out = validate_action_for_category(
        "scanner_coverage",
        {"type": "stale_alert", "stale_after_days": 7},
    )
    assert out.stale_after_days == 7
    assert out.alert_channel_id is None


@pytest.mark.parametrize("days", [0, 366])
def test_scanner_coverage_stale_after_days_bounds(days):
    with pytest.raises(ValueError):
        validate_action_for_category(
            "scanner_coverage",
            {"type": "stale_alert", "stale_after_days": days, "alert_channel_id": 3},
        )


def test_scanner_coverage_unknown_type_rejected():
    with pytest.raises(ValueError):
        validate_action_for_category(
            "scanner_coverage", {"type": "carrier_pigeon", "required_scanners": ["code_scanning"]}
        )


# ── auto_dismiss ─────────────────────────────────────────────────────────────

def test_auto_dismiss_applies_defaults():
    out = validate_action_for_category("auto_dismiss", {"reason": "duplicate finding"})
    assert out.rate_alarm_pct == 50.0
    assert out.rate_alarm_window_minutes == 60
    assert out.audit_note is None


def test_auto_dismiss_reason_too_short():
    with pytest.raises(ValueError):
        validate_action_for_category("auto_dismiss", {"reason": "ab"})


@pytest.mark.parametrize("pct", [0.0, 100.1])
def test_auto_dismiss_rate_alarm_pct_bounds(pct):
    with pytest.raises(ValueError):
        validate_action_for_category(
            "auto_dismiss", {"reason": "duplicate", "rate_alarm_pct": pct}
        )


@pytest.mark.parametrize("minutes", [4, 10081])
def test_auto_dismiss_window_bounds(minutes):
    with pytest.raises(ValueError):
        validate_action_for_category(
            "auto_dismiss", {"reason": "duplicate", "rate_alarm_window_minutes": minutes}
        )


# ── data_retention (discriminated) ───────────────────────────────────────────

def test_data_retention_archive_valid():
    out = validate_action_for_category("data_retention", {"type": "archive", "after_days": 30})
    assert out.after_days == 30


def test_data_retention_delete_valid():
    out = validate_action_for_category("data_retention", {"type": "delete", "after_days": 90})
    assert out.after_days == 90


def test_data_retention_delete_floor_is_higher_than_archive():
    # Archive allows 30 days; delete must wait at least 90 — 30 is invalid for delete.
    with pytest.raises(ValueError):
        validate_action_for_category("data_retention", {"type": "delete", "after_days": 30})


def test_data_retention_archive_below_floor_rejected():
    with pytest.raises(ValueError):
        validate_action_for_category("data_retention", {"type": "archive", "after_days": 29})


def test_data_retention_unknown_type_rejected():
    with pytest.raises(ValueError):
        validate_action_for_category("data_retention", {"type": "shred", "after_days": 100})

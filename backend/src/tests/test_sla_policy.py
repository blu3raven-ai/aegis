"""Tests for SLA policy dataclass validation and defaults."""
from __future__ import annotations

import pytest

from src.sla.policy import DEFAULT_POLICIES, SlaPolicy, VALID_SEVERITIES


def test_default_policies_cover_all_severities():
    sevs = {p.severity for p in DEFAULT_POLICIES}
    assert sevs == VALID_SEVERITIES


def test_default_deadlines():
    defaults = {p.severity: p.deadline_days for p in DEFAULT_POLICIES}
    assert defaults["critical"] == 7
    assert defaults["high"] == 14
    assert defaults["medium"] == 30
    assert defaults["low"] == 90


def test_all_defaults_enabled():
    assert all(p.enabled for p in DEFAULT_POLICIES)


def test_validate_ok():
    p = SlaPolicy("critical", 7, True)
    p.validate()  # should not raise


def test_validate_zero_deadline_raises():
    p = SlaPolicy("critical", 0, True)
    with pytest.raises(ValueError, match="greater than 0"):
        p.validate()


def test_validate_negative_deadline_raises():
    p = SlaPolicy("high", -1, True)
    with pytest.raises(ValueError, match="greater than 0"):
        p.validate()


def test_validate_unknown_severity_raises():
    p = SlaPolicy("unknown", 7, True)
    with pytest.raises(ValueError, match="severity"):
        p.validate()

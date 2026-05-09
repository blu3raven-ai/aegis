"""Tests for shared finding CRUD and analytics queries."""
from __future__ import annotations

import pytest

from src.shared.finding_queries import compute_severity_counts


def test_compute_severity_counts_empty():
    rows = []
    result = compute_severity_counts(rows)
    assert result == {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


def test_compute_severity_counts_mixed():
    rows = [
        ("critical", 3),
        ("high", 5),
        ("medium", 2),
        ("low", 1),
    ]
    result = compute_severity_counts(rows)
    assert result == {"total": 11, "critical": 3, "high": 5, "medium": 2, "low": 1}


def test_compute_severity_counts_unknown_severity_still_totaled():
    rows = [("critical", 2), ("unknown", 3)]
    result = compute_severity_counts(rows)
    assert result["total"] == 5
    assert result["critical"] == 2

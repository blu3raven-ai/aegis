"""Tests for the daily LLM token usage ledger."""
from __future__ import annotations

from uuid import uuid4

import pytest

from src.settings.llm.usage import daily_remaining, record_usage


@pytest.fixture
def org_id() -> str:
    return f"test-org-{uuid4()}"


def test_first_record_creates_row(db_session, org_id):
    record_usage(org_id=org_id, tokens_in=100, tokens_out=200, scans=1)
    assert daily_remaining(org_id=org_id, daily_budget=10_000) == 9_700


def test_multiple_records_accumulate(db_session, org_id):
    record_usage(org_id=org_id, tokens_in=100, tokens_out=100, scans=1)
    record_usage(org_id=org_id, tokens_in=200, tokens_out=200, scans=1)
    assert daily_remaining(org_id=org_id, daily_budget=10_000) == 9_400


def test_remaining_clamped_at_zero(db_session, org_id):
    record_usage(org_id=org_id, tokens_in=10_000, tokens_out=0, scans=1)
    assert daily_remaining(org_id=org_id, daily_budget=5_000) == 0


def test_remaining_with_no_usage(db_session, org_id):
    assert daily_remaining(org_id=org_id, daily_budget=10_000) == 10_000

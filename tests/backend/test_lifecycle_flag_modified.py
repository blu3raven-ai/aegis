"""Tests confirming flag_modified is called on detail updates in the lifecycle engine.

SQLAlchemy does not auto-detect in-place replacement of JSONB dict columns — assigning
a new dict object to `prev.detail` looks identical to the ORM tracker because the column
type has no change-detection hook (unlike MutableDict.as_mutable()).  Without an explicit
`flag_modified(prev, "detail")` call the session silently skips the column in the UPDATE,
leaving stale data in the DB.

These tests confirm:
  1. flag_modified is called for every branch where prev.detail is replaced.
  2. The new detail value is actually assigned before flag_modified is called.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from src.shared.lifecycle import apply_lifecycle, ScanContext, LifecycleHooks


class _SimpleHooks(LifecycleHooks):
    tool = "code_scanning"

    def compute_identity_key(self, raw: dict) -> str:
        return raw.get("key", "")

    def initial_state(self, raw: dict) -> str:
        return "open"

    def extract_repo(self, raw: dict) -> str | None:
        return "acme-org/api"

    def extract_severity(self, raw: dict) -> str | None:
        return raw.get("severity", "medium")

    def extract_detail(self, raw: dict) -> dict:
        return {"code_window": raw.get("code_window", ""), "reachability": raw.get("reachability")}

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return True


def _make_prev(state: str = "open", identity_key: str = "k1") -> MagicMock:
    f = MagicMock()
    f.state = state
    f.identity_key = identity_key
    f.detail = {"code_window": "", "reachability": None}
    f.id = "finding-id-1"
    f.severity = "medium"
    return f


def _run_lifecycle_with_mock_db(
    current_findings: list[dict],
    prev_findings: list,
    decision_map: dict | None = None,
) -> MagicMock:
    """
    Run apply_lifecycle with mocked DB helpers.  Returns the mock for flag_modified
    so the caller can assert on it.

    The inner async function `_run(session)` is extracted from run_db's argument,
    then executed with a mock session and mocked query helpers.
    """
    hooks = _SimpleHooks()
    ctx = ScanContext(tool="code_scanning", org="acme-org", run_id="run-1")
    dm = decision_map or {}

    captured: list = []

    def capture_run_db(coro_fn):
        captured.append(coro_fn)

    with (
        patch("src.shared.lifecycle.run_db", side_effect=capture_run_db),
        patch("src.shared.lifecycle.read_findings", new_callable=AsyncMock, return_value=prev_findings),
        patch("src.shared.lifecycle.read_decisions_for_org", new_callable=AsyncMock, return_value=dm),
        patch("src.shared.lifecycle.insert_event", new_callable=AsyncMock),
        patch("src.shared.lifecycle.update_finding_state", new_callable=AsyncMock),
        patch("src.shared.lifecycle.upsert_finding", new_callable=AsyncMock),
        patch("src.shared.lifecycle.flag_modified") as mock_fm,
    ):
        apply_lifecycle(hooks, ctx, current_findings)
        assert captured, "run_db must have been called"
        session = AsyncMock()
        asyncio.run(captured[0](session))

    return mock_fm


# ── open existing finding ─────────────────────────────────────────────────────


def test_flag_modified_called_for_open_existing_finding():
    """Normal re-scan of an existing open finding must call flag_modified on detail."""
    prev = _make_prev(state="open")
    new_code_window = "def transcribe_audio():\n    backend_response = requests.post(URL)\n"

    mock_fm = _run_lifecycle_with_mock_db(
        current_findings=[{"key": "k1", "code_window": new_code_window}],
        prev_findings=[prev],
    )

    mock_fm.assert_called_with(prev, "detail")


def test_detail_is_assigned_before_flag_modified_for_open_finding():
    """The new detail dict must be on prev.detail when flag_modified is called."""
    prev = _make_prev(state="open")
    new_window = "updated code window"

    calls_with_detail: list[dict] = []

    def spy_flag_modified(obj, attr):
        calls_with_detail.append(dict(obj.detail))

    with (
        patch("src.shared.lifecycle.run_db", side_effect=lambda fn: None),
    ):
        # Use the full patched execution path
        pass

    # Run for real to capture the side effect
    hooks = _SimpleHooks()
    ctx = ScanContext(tool="code_scanning", org="acme-org", run_id="run-1")

    captured: list = []
    with (
        patch("src.shared.lifecycle.run_db", side_effect=lambda fn: captured.append(fn)),
        patch("src.shared.lifecycle.read_findings", new_callable=AsyncMock, return_value=[prev]),
        patch("src.shared.lifecycle.read_decisions_for_org", new_callable=AsyncMock, return_value={}),
        patch("src.shared.lifecycle.insert_event", new_callable=AsyncMock),
        patch("src.shared.lifecycle.update_finding_state", new_callable=AsyncMock),
        patch("src.shared.lifecycle.upsert_finding", new_callable=AsyncMock),
        patch("src.shared.lifecycle.flag_modified", side_effect=spy_flag_modified),
    ):
        apply_lifecycle(hooks, ctx, [{"key": "k1", "code_window": new_window}])
        asyncio.run(captured[0](AsyncMock()))

    assert len(calls_with_detail) >= 1
    assert calls_with_detail[0]["code_window"] == new_window


# ── dismissed existing finding ────────────────────────────────────────────────


def test_flag_modified_called_for_dismissed_existing_finding():
    """Dismissed findings that reappear must also have their detail persisted."""
    prev = _make_prev(state="dismissed")
    dismissed_decision = MagicMock()
    dismissed_decision.status = "dismissed"

    mock_fm = _run_lifecycle_with_mock_db(
        current_findings=[{"key": "k1", "code_window": "new context"}],
        prev_findings=[prev],
        decision_map={"k1": dismissed_decision},
    )

    mock_fm.assert_called_with(prev, "detail")


# ── fixed→reopened finding ────────────────────────────────────────────────────


def test_flag_modified_called_for_fixed_reopened_finding():
    """When a previously fixed finding reappears, flag_modified must be called."""
    prev = _make_prev(state="fixed")

    mock_fm = _run_lifecycle_with_mock_db(
        current_findings=[{"key": "k1", "code_window": "reopened context"}],
        prev_findings=[prev],
    )

    mock_fm.assert_called_with(prev, "detail")


# ── no false marks for absent findings ───────────────────────────────────────


def test_flag_modified_not_called_for_new_findings():
    """New findings go through upsert_finding, not prev.detail assignment."""
    # No prev findings → this is a new finding, upsert_finding is called instead
    mock_fm = _run_lifecycle_with_mock_db(
        current_findings=[{"key": "new-key", "code_window": "some code"}],
        prev_findings=[],
    )

    mock_fm.assert_not_called()

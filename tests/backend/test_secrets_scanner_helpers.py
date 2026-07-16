"""Pure-function coverage for secrets/scanner.py — ANSI stripping, log-tail
management, progress math, and the run-status state machine. No DB required."""
from __future__ import annotations

from src.secrets.scanner import (
    apply_run_transition,
    as_record,
    can_transition_run_status,
    compute_running_percent,
    keep_tail,
    reconcile_expected_repos,
    strip_ansi,
)


def test_strip_ansi_removes_color_codes():
    assert strip_ansi("\x1b[31mred\x1b[0m text") == "red text"
    assert strip_ansi("plain") == "plain"


def test_keep_tail_appends_split_lines_and_caps():
    out = keep_tail(["a"], "b\nc\r\nd", limit=3)
    assert out == ["b", "c", "d"]  # last 3, blank lines dropped, \r\n + \n both split


def test_keep_tail_drops_blank_lines():
    assert keep_tail([], "x\n\n\ny", limit=10) == ["x", "y"]


# --- progress math ---

def test_reconcile_expected_repos_takes_the_max():
    assert reconcile_expected_repos(5, 3, 2) == 5
    assert reconcile_expected_repos(1, 7, 2) == 7   # scanned exceeds declared
    assert reconcile_expected_repos(0, 0, 4) == 4   # finished exceeds
    assert reconcile_expected_repos("bad", 0, 0) is None  # nothing known → None


def test_compute_running_percent_with_known_total():
    # halfway through a known 10 repos → ~47%, capped in [2,94]
    pct = compute_running_percent(10, 5, 5)
    assert 2 <= pct <= 94 and abs(pct - (5 / 10) * 94) < 0.01


def test_compute_running_percent_never_exceeds_ceiling():
    assert compute_running_percent(10, 10, 10) == 94  # all done but still "running" → capped at 94
    assert compute_running_percent(None, 0, 0) == 2   # nothing yet → floor


def test_as_record_passthrough_and_default():
    assert as_record({"a": 1}) == {"a": 1}
    assert as_record("not a dict") == {}
    assert as_record(None) == {}


# --- run-status state machine ---

def test_can_transition_follows_the_map():
    assert can_transition_run_status("queued", "running") is True
    assert can_transition_run_status("running", "ingesting") is True
    assert can_transition_run_status("ingesting", "completed") is True
    # terminal states go nowhere
    assert can_transition_run_status("completed", "running") is False
    assert can_transition_run_status("failed", "running") is False
    # illegal skip
    assert can_transition_run_status("queued", "completed") is False


def test_can_transition_same_status_is_idempotent():
    assert can_transition_run_status("running", "running") is True


def test_apply_run_transition_rejects_illegal_move():
    assert apply_run_transition({"status": "completed"}, "running") is None


def test_apply_run_transition_updates_status_and_stamps():
    out = apply_run_transition({"status": "queued", "org": "x"}, "running", {"note": "go"})
    assert out["status"] == "running" and out["org"] == "x" and out["note"] == "go"
    assert out["lastStatusTransitionAt"] and out["lastHeartbeatAt"]


def test_apply_run_transition_honors_explicit_heartbeat():
    out = apply_run_transition({"status": "running"}, "ingesting", {"lastHeartbeatAt": "2026-01-01T00:00:00Z"})
    assert out["lastHeartbeatAt"] == "2026-01-01T00:00:00Z"

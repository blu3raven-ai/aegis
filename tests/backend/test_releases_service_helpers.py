"""Pure-logic coverage for history/releases/service.py — the release verdict gate
(no_go/warn/go/pending) and the status/actor/cwe/scanner parsers it depends on."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.history.releases.service import (
    _compute_verdict,
    _decode_cursor,
    _encode_cursor,
    _first_cwe,
    _normalise_status,
    _scanner_of,
    _triggered_by,
)


def test_compute_verdict_blocker_beats_warn_and_status():
    # A critical blocks the release regardless of everything else.
    assert _compute_verdict("completed", {"critical": 1, "high": 5}) == "no_go"


def test_compute_verdict_warn_when_only_highs():
    assert _compute_verdict("completed", {"critical": 0, "high": 3}) == "warn"


def test_compute_verdict_clean_paths():
    assert _compute_verdict("completed", {}) == "go"          # clean + done
    assert _compute_verdict("running", {}) == "pending"       # in flight
    assert _compute_verdict("queued", {}) == "pending"
    assert _compute_verdict("failed", {}) == "unknown"        # terminal non-completed


def test_normalise_status_maps_and_raises():
    assert _normalise_status("ingesting") == "running"   # collapsed
    assert _normalise_status("cancelled") == "failed"
    assert _normalise_status("COMPLETED") == "completed"  # case-insensitive
    with pytest.raises(ValueError, match="unknown ScanRun status"):
        _normalise_status("teleporting")


def test_triggered_by_ci_vs_user():
    ci = _triggered_by({"source": "github_actions", "submitted_by": "bot"})
    assert ci["actor_type"] == "ci" and ci["actor_id"] == "bot"
    ci_default = _triggered_by({"source": "ci"})
    assert ci_default["actor_id"] == "ci"
    user = _triggered_by({"source": "manual", "submitted_by": "alice"})
    assert user["actor_type"] == "user" and user["actor_id"] == "alice"
    assert _triggered_by({})["actor_id"] == "unknown"


def test_first_cwe_list_string_none():
    assert _first_cwe({"cwe": ["CWE-89", "CWE-79"]}) == "CWE-89"
    assert _first_cwe({"cwe": "CWE-22"}) == "CWE-22"
    assert _first_cwe({"cwe": []}) is None
    assert _first_cwe(None) is None


def test_scanner_of_prefers_engine_then_tool():
    assert _scanner_of(SimpleNamespace(engine="trivy", tool="dependencies")) == "trivy"
    assert _scanner_of(SimpleNamespace(engine=None, tool="sast")) == "sast"
    assert _scanner_of(SimpleNamespace(engine=None, tool=None)) == "unknown"


def test_cursor_round_trip():
    assert _decode_cursor(_encode_cursor({"id": "r1", "t": 5})) == {"id": "r1", "t": 5}

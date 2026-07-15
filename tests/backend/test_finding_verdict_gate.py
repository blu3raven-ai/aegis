"""Recall-safety gate: an ungrounded ``ruled_out`` must not hide a finding.

The grounding predicate is exercised directly here; the full upsert integration
(which downgrades the promoted verdict) runs in the DB-backed suite in CI.
"""
from __future__ import annotations

from src.shared.finding_queries import _ruled_out_grounded


def test_grounded_via_evidence_file():
    evidence = [{"kind": "code", "file": "app/db.py", "line": 12}]
    assert _ruled_out_grounded(evidence, None) is True


def test_grounded_via_ruled_out_reason_file():
    meta = {"ruled_out_reason": {"file": "app/guard.py", "line": 3}}
    assert _ruled_out_grounded([], meta) is True


def test_ungrounded_when_no_file_anywhere():
    # Evidence without a file citation and metadata without a ruled_out_reason
    # file — a suppression we can't tie to real code, so not grounded.
    assert _ruled_out_grounded([{"kind": "note", "text": "looks safe"}], {"reason": "x"}) is False


def test_ungrounded_on_empty_inputs():
    assert _ruled_out_grounded(None, None) is False
    assert _ruled_out_grounded([], {}) is False


def test_ungrounded_when_reason_file_blank():
    assert _ruled_out_grounded([], {"ruled_out_reason": {"file": ""}}) is False

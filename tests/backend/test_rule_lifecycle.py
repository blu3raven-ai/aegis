"""Tests for Rule 4: LifecycleRule — file deletion → close findings."""
from __future__ import annotations

from unittest.mock import MagicMock, call

import pytest

from src.correlation.rule import RuleContext
from src.correlation.rules.lifecycle import LifecycleRule


ORG = "acme-org"
REPO = "acme-org/lifecycle-repo"


def _make_ctx(open_findings=None, emit=None):
    state = MagicMock()
    state.lookup_open_findings.return_value = open_findings or []
    return RuleContext(state=state, argus=None, emit=emit or MagicMock())


def _push_event(deleted_files=None, repo=REPO):
    return {
        "_stream_id": "1-0",
        "event_id": "evt-push-001",
        "event_type": "code.push",
        "org_id": ORG,
        "source_component": "git_sync",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "repo_id": repo,
            "after_sha": "abc123",
            "deleted_files": deleted_files or [],
        },
    }


# ── triggers ──────────────────────────────────────────────────────────────────


def test_lifecycle_trigger_is_code_push():
    rule = LifecycleRule()
    assert "code.push" in rule.triggers


# ── no deleted files ──────────────────────────────────────────────────────────


def test_no_deleted_files_no_close():
    ctx = _make_ctx()
    rule = LifecycleRule()
    rule.evaluate(_push_event(deleted_files=[]), ctx)
    ctx.emit.emit_close.assert_not_called()


def test_missing_deleted_files_key_no_close():
    ctx = _make_ctx()
    rule = LifecycleRule()
    event = _push_event()
    del event["payload"]["deleted_files"]
    rule.evaluate(event, ctx)
    ctx.emit.emit_close.assert_not_called()


# ── single deleted file ───────────────────────────────────────────────────────


def test_deleted_file_closes_matching_findings():
    findings = [
        {"id": 1, "tool": "code_scanning", "org": ORG, "repo": REPO,
         "state": "open", "severity": "high", "detail": {"file_path": "src/app.py"}},
        {"id": 2, "tool": "code_scanning", "org": ORG, "repo": REPO,
         "state": "open", "severity": "medium", "detail": {"file_path": "src/app.py"}},
    ]
    ctx = _make_ctx(open_findings=findings)
    rule = LifecycleRule()
    rule.evaluate(_push_event(deleted_files=["src/app.py"]), ctx)

    assert ctx.emit.emit_close.call_count == 2
    closed_ids = {c.args[0] for c in ctx.emit.emit_close.call_args_list}
    assert closed_ids == {1, 2}


def test_deleted_file_with_no_findings_is_noop():
    ctx = _make_ctx(open_findings=[])
    rule = LifecycleRule()
    rule.evaluate(_push_event(deleted_files=["src/old.py"]), ctx)
    ctx.emit.emit_close.assert_not_called()


# ── multiple deleted files ────────────────────────────────────────────────────


def test_multiple_deleted_files_closes_all():
    findings_a = [{"id": 10, "tool": "code_scanning", "org": ORG, "repo": REPO,
                   "state": "open", "severity": "high", "detail": {}}]
    findings_b = [{"id": 20, "tool": "code_scanning", "org": ORG, "repo": REPO,
                   "state": "open", "severity": "low", "detail": {}}]

    call_map = {
        "src/a.py": findings_a,
        "src/b.py": findings_b,
    }

    state = MagicMock()
    state.lookup_open_findings.side_effect = lambda **kw: call_map.get(kw.get("file_path"), [])
    emit = MagicMock()
    ctx = RuleContext(state=state, argus=None, emit=emit)

    rule = LifecycleRule()
    rule.evaluate(_push_event(deleted_files=["src/a.py", "src/b.py"]), ctx)

    assert emit.emit_close.call_count == 2
    closed_ids = {c.args[0] for c in emit.emit_close.call_args_list}
    assert closed_ids == {10, 20}


# ── reason contains file path ─────────────────────────────────────────────────


def test_close_reason_contains_file_path():
    findings = [{"id": 99, "tool": "code_scanning", "org": ORG, "repo": REPO,
                 "state": "open", "severity": "high", "detail": {}}]
    ctx = _make_ctx(open_findings=findings)
    rule = LifecycleRule()
    rule.evaluate(_push_event(deleted_files=["src/deleted.py"]), ctx)

    close_kwargs = ctx.emit.emit_close.call_args.kwargs
    assert "src/deleted.py" in close_kwargs["reason"]


# ── missing org or repo ───────────────────────────────────────────────────────


def test_event_without_repo_is_skipped():
    ctx = _make_ctx()
    rule = LifecycleRule()
    event = _push_event(deleted_files=["src/x.py"])
    del event["payload"]["repo_id"]
    rule.evaluate(event, ctx)
    ctx.emit.emit_close.assert_not_called()


def test_event_without_org_is_skipped():
    ctx = _make_ctx()
    rule = LifecycleRule()
    event = _push_event(deleted_files=["src/x.py"])
    event["org_id"] = ""
    rule.evaluate(event, ctx)
    ctx.emit.emit_close.assert_not_called()

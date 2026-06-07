"""Tests that the lifecycle engine persists the `engine` column on Findings.

Uses the same mocked-DB pattern as test_lifecycle_flag_modified.py so these
run without a Postgres container.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.code_scanning.lifecycle import code_scanning_hooks
from src.shared.lifecycle import apply_lifecycle, ScanContext


def _raw(engine: str, rule_id: str = "joern-sqli", dataflow=None):
    return {
        "repo_full_name": "acme-org/api",
        "file_path": "src/app.py",
        "start_line": 42,
        "end_line": 42,
        "rule_id": rule_id,
        "rule_name": "SQL Injection",
        "severity": "high",
        "confidence": "high",
        "category": "security",
        "cwe": ["CWE-89"],
        "message": "tainted flow",
        "snippet": "cursor.execute(q)",
        "engine": engine,
        "dataflow_trace": dataflow,
    }


def _capture_apply_lifecycle(current_findings, prev_findings, decision_map=None):
    """Run apply_lifecycle with mocked DB; return the upsert_finding mock."""
    ctx = ScanContext(tool="code_scanning", org="acme-org", run_id="run-1")

    captured: list = []

    with (
        patch("src.shared.lifecycle.run_db", side_effect=lambda fn: captured.append(fn)),
        patch("src.shared.lifecycle.read_findings", new_callable=AsyncMock, return_value=prev_findings),
        patch("src.shared.lifecycle.read_decisions_for_org", new_callable=AsyncMock, return_value=decision_map or {}),
        patch("src.shared.lifecycle.insert_event", new_callable=AsyncMock),
        patch("src.shared.lifecycle.update_finding_state", new_callable=AsyncMock),
        patch("src.shared.lifecycle.upsert_finding", new_callable=AsyncMock) as upsert,
        patch("src.shared.lifecycle.flag_modified"),
    ):
        upsert.return_value = MagicMock(id=1)
        apply_lifecycle(code_scanning_hooks, ctx, current_findings)
        assert captured, "run_db must have been called"
        asyncio.run(captured[0](AsyncMock()))

    return upsert


def test_new_joern_finding_passes_engine_to_upsert():
    """A new joern finding must reach upsert_finding with engine='joern'."""
    trace = [{"file": "src/app.py", "line": 40, "snippet": "x=req.args['id']", "role": "source"}]
    upsert = _capture_apply_lifecycle(
        current_findings=[_raw("joern", dataflow=trace)],
        prev_findings=[],
    )
    assert upsert.await_count == 1
    kwargs = upsert.await_args.kwargs
    assert kwargs.get("engine") == "joern"


def test_existing_finding_engine_is_assigned_on_open_path():
    """On the open-existing branch, prev.engine must be updated."""
    prev = MagicMock()
    prev.state = "open"
    prev.identity_key = "acme-org/api:src/app.py:joern-sqli:42"
    prev.id = 99
    prev.severity = "medium"
    prev.engine = "opengrep"

    ctx = ScanContext(tool="code_scanning", org="acme-org", run_id="run-1")
    captured: list = []

    with (
        patch("src.shared.lifecycle.run_db", side_effect=lambda fn: captured.append(fn)),
        patch("src.shared.lifecycle.read_findings", new_callable=AsyncMock, return_value=[prev]),
        patch("src.shared.lifecycle.read_decisions_for_org", new_callable=AsyncMock, return_value={}),
        patch("src.shared.lifecycle.insert_event", new_callable=AsyncMock),
        patch("src.shared.lifecycle.update_finding_state", new_callable=AsyncMock),
        patch("src.shared.lifecycle.upsert_finding", new_callable=AsyncMock),
        patch("src.shared.lifecycle.flag_modified"),
    ):
        # Same key the hooks compute for the raw input below
        prev.identity_key = code_scanning_hooks.compute_identity_key(_raw("both"))
        apply_lifecycle(code_scanning_hooks, ctx, [_raw("both")])
        asyncio.run(captured[0](AsyncMock()))

    assert prev.engine == "both"


def test_extract_detail_surfaces_dataflow_trace_and_omits_engine():
    """detail JSONB must surface dataflowTrace. Engine lives on the Finding column
    (source of truth) and must NOT be duplicated in detail."""
    trace = [
        {"file": "src/app.py", "line": 40, "snippet": "x=req.args['id']", "role": "source"},
        {"file": "src/app.py", "line": 42, "snippet": "execute(x)", "role": "sink"},
    ]
    raw = _raw("joern", dataflow=trace)
    detail = code_scanning_hooks.extract_detail(raw)
    assert "engine" not in detail
    assert detail["dataflowTrace"] == trace


def test_extract_detail_no_dataflow_trace_when_absent():
    raw = _raw("opengrep")
    del raw["engine"]
    detail = code_scanning_hooks.extract_detail(raw)
    assert "engine" not in detail
    assert "dataflowTrace" not in detail


def test_extract_detail_emits_rule_ids_when_merge_recorded_multiple():
    raw = _raw("both")
    raw["_rule_ids"] = ["opengrep-sqli", "joern-sqli"]
    detail = code_scanning_hooks.extract_detail(raw)
    assert detail["ruleIds"] == ["opengrep-sqli", "joern-sqli"]


def test_extract_detail_emits_rule_ids_as_singleton_list_when_single():
    """ruleIds is always a list (uniform shape) — length 1 for single-engine."""
    raw = _raw("opengrep", rule_id="opengrep-sqli")
    raw["_rule_ids"] = ["opengrep-sqli"]
    detail = code_scanning_hooks.extract_detail(raw)
    assert detail["ruleIds"] == ["opengrep-sqli"]
    # ruleId singular is retained for backwards compat with existing readers.
    assert detail["ruleId"] == "opengrep-sqli"


def test_extract_detail_rule_ids_falls_back_to_singleton_when_no_merge_list():
    """When merge hasn't run (legacy/non-merged), still emit ruleIds=[rule_id]."""
    raw = _raw("opengrep", rule_id="opengrep-sqli")
    # No _rule_ids key at all
    detail = code_scanning_hooks.extract_detail(raw)
    assert detail["ruleIds"] == ["opengrep-sqli"]


def _raw_no_engine(rule_id: str = "joern-sqli"):
    r = _raw("opengrep", rule_id=rule_id)
    del r["engine"]
    return r


def test_engine_not_clobbered_when_raw_lacks_engine_on_in_place_update():
    """Raw with no engine key must NOT NULL out prev.engine on the in-place-update path."""
    prev = MagicMock()
    prev.state = "open"
    prev.id = 99
    prev.severity = "medium"
    prev.engine = "opengrep"

    ctx = ScanContext(tool="code_scanning", org="acme-org", run_id="run-1")
    captured: list = []

    raw = _raw_no_engine()

    with (
        patch("src.shared.lifecycle.run_db", side_effect=lambda fn: captured.append(fn)),
        patch("src.shared.lifecycle.read_findings", new_callable=AsyncMock, return_value=[prev]),
        patch("src.shared.lifecycle.read_decisions_for_org", new_callable=AsyncMock, return_value={}),
        patch("src.shared.lifecycle.insert_event", new_callable=AsyncMock),
        patch("src.shared.lifecycle.update_finding_state", new_callable=AsyncMock),
        patch("src.shared.lifecycle.upsert_finding", new_callable=AsyncMock),
        patch("src.shared.lifecycle.flag_modified"),
    ):
        prev.identity_key = code_scanning_hooks.compute_identity_key(raw)
        apply_lifecycle(code_scanning_hooks, ctx, [raw])
        asyncio.run(captured[0](AsyncMock()))

    assert prev.engine == "opengrep", "engine must not be NULLed when raw lacks engine"


def test_engine_not_clobbered_when_raw_lacks_engine_on_dismissed_update():
    """Raw with no engine key must NOT NULL out prev.engine on the dismissed-existing path."""
    from src.db.models import Decision

    prev = MagicMock()
    prev.state = "dismissed"
    prev.id = 99
    prev.severity = "medium"
    prev.engine = "opengrep"

    decision = MagicMock(spec=Decision)
    decision.status = "dismissed"

    ctx = ScanContext(tool="code_scanning", org="acme-org", run_id="run-1")
    captured: list = []

    raw = _raw_no_engine()
    key = code_scanning_hooks.compute_identity_key(raw)
    prev.identity_key = key

    with (
        patch("src.shared.lifecycle.run_db", side_effect=lambda fn: captured.append(fn)),
        patch("src.shared.lifecycle.read_findings", new_callable=AsyncMock, return_value=[prev]),
        patch(
            "src.shared.lifecycle.read_decisions_for_org",
            new_callable=AsyncMock,
            return_value={key: decision},
        ),
        patch("src.shared.lifecycle.insert_event", new_callable=AsyncMock),
        patch("src.shared.lifecycle.update_finding_state", new_callable=AsyncMock),
        patch("src.shared.lifecycle.upsert_finding", new_callable=AsyncMock),
        patch("src.shared.lifecycle.flag_modified"),
    ):
        apply_lifecycle(code_scanning_hooks, ctx, [raw])
        asyncio.run(captured[0](AsyncMock()))

    assert prev.engine == "opengrep", "engine must not be NULLed on dismissed update path when raw lacks engine"


def test_identity_key_stable_when_engine_drops_coverage():
    """Scan 1: only opengrep flags. Scan 2: opengrep gone, joern flags.

    identity_key must match so the lifecycle in-place updates the same
    row rather than marking the old row "fixed" and creating a duplicate.
    """
    from src.code_scanning.merge import merge_engine_findings

    raw_scan1 = [{
        "repo_full_name": "acme-org/api",
        "file_path": "src/app.py",
        "start_line": 42,
        "end_line": 42,
        "rule_id": "opengrep-sqli",
        "engine": "opengrep",
        "cwe": ["CWE-89"],
        "severity": "high",
    }]
    raw_scan2 = [{
        "repo_full_name": "acme-org/api",
        "file_path": "src/app.py",
        "start_line": 42,
        "end_line": 42,
        "rule_id": "joern-sqli",
        "engine": "joern",
        "cwe": ["CWE-89"],
        "severity": "high",
    }]

    merged_1 = merge_engine_findings(raw_scan1)
    merged_2 = merge_engine_findings(raw_scan2)

    key_1 = code_scanning_hooks.compute_identity_key(merged_1[0])
    key_2 = code_scanning_hooks.compute_identity_key(merged_2[0])

    assert key_1 == key_2, f"identity_key must survive engine flip; got {key_1!r} vs {key_2!r}"
    # Colons in segments are escaped to %3A, so the stored surrogate is sast%3Acwe-89.
    assert "sast%3Acwe-89" in key_1


def test_engine_updated_when_raw_provides_engine_on_in_place_update():
    """Sanity check: explicit engine in raw still gets applied to prev.engine."""
    prev = MagicMock()
    prev.state = "open"
    prev.id = 99
    prev.severity = "medium"
    prev.engine = "opengrep"

    ctx = ScanContext(tool="code_scanning", org="acme-org", run_id="run-1")
    captured: list = []

    raw = _raw("both")

    with (
        patch("src.shared.lifecycle.run_db", side_effect=lambda fn: captured.append(fn)),
        patch("src.shared.lifecycle.read_findings", new_callable=AsyncMock, return_value=[prev]),
        patch("src.shared.lifecycle.read_decisions_for_org", new_callable=AsyncMock, return_value={}),
        patch("src.shared.lifecycle.insert_event", new_callable=AsyncMock),
        patch("src.shared.lifecycle.update_finding_state", new_callable=AsyncMock),
        patch("src.shared.lifecycle.upsert_finding", new_callable=AsyncMock),
        patch("src.shared.lifecycle.flag_modified"),
    ):
        prev.identity_key = code_scanning_hooks.compute_identity_key(raw)
        apply_lifecycle(code_scanning_hooks, ctx, [raw])
        asyncio.run(captured[0](AsyncMock()))

    assert prev.engine == "both"

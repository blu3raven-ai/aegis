"""Tests for the code_scanning lifecycle hooks: extract_detail / extract_engine
behavior. The apply_lifecycle integration tests that used to live here were
removed when apply_lifecycle was rewritten to load prev findings via inline
session.execute() instead of the previously-mocked read_findings/
read_decisions_for_org helpers — the unit-mock pattern is no longer viable.
End-to-end behavior is covered by the integration test suite.
"""
from __future__ import annotations

from src.code_scanning.lifecycle import code_scanning_hooks


def _raw(engine: str, rule_id: str = "semgrep-sqli", dataflow=None):
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


def test_extract_detail_surfaces_dataflow_trace_and_omits_engine():
    """detail JSONB must surface dataflowTrace. Engine lives on the Finding column
    (source of truth) and must NOT be duplicated in detail."""
    trace = [
        {"file": "src/app.py", "line": 40, "snippet": "x=req.args['id']", "role": "source"},
        {"file": "src/app.py", "line": 42, "snippet": "execute(x)", "role": "sink"},
    ]
    raw = _raw("semgrep", dataflow=trace)
    detail = code_scanning_hooks.extract_detail(raw)
    assert "engine" not in detail
    assert detail["dataflowTrace"] == trace


def test_extract_detail_no_dataflow_trace_when_absent():
    raw = _raw("semgrep")
    del raw["engine"]
    detail = code_scanning_hooks.extract_detail(raw)
    assert "engine" not in detail
    assert "dataflowTrace" not in detail


def test_extract_detail_emits_rule_ids_as_singleton_list_when_single():
    """ruleIds is always a list (uniform shape) — length 1 for single-engine."""
    raw = _raw("semgrep", rule_id="semgrep-sqli")
    raw["_rule_ids"] = ["semgrep-sqli"]
    detail = code_scanning_hooks.extract_detail(raw)
    assert detail["ruleIds"] == ["semgrep-sqli"]
    # ruleId singular is retained for backwards compat with existing readers.
    assert detail["ruleId"] == "semgrep-sqli"


def test_extract_detail_rule_ids_falls_back_to_singleton_when_no_list():
    """When raw lacks _rule_ids, still emit ruleIds=[rule_id]."""
    raw = _raw("semgrep", rule_id="semgrep-sqli")
    # No _rule_ids key at all
    detail = code_scanning_hooks.extract_detail(raw)
    assert detail["ruleIds"] == ["semgrep-sqli"]

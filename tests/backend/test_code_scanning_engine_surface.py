"""Tests that engine attribution and dataflow trace are surfaced through
the storage shaper and the GraphQL resolver.

The Finding ORM column `engine` is the source of truth for engine attribution;
`detail["dataflowTrace"]` and `detail["ruleIds"]` carry the rich payload.
Both must be exposed in API/GraphQL dicts so the frontend can render them
without inspecting the raw `detail` blob.
"""
from __future__ import annotations

from unittest.mock import patch

from src.graphql.code_scanning_resolvers import (
    CodeScanningDataflowStep,
    _make_dataflow_trace,
    code_scanning_findings,
)
from src.storage import _finding_to_code_scanning_dict


class _MockFinding:
    """Minimal stand-in for the Finding ORM model."""

    def __init__(
        self,
        detail: dict,
        *,
        engine: str | None = None,
        org: str = "acme-org",
        repo: str = "example-repo",
    ):
        from src.shared.finding_queryable_fields import extract_queryable_fields
        self.state = "open"
        self.first_seen_at = None
        self.fixed_at = None
        self.org = org
        self.repo = repo
        self.severity = "high"
        self.detail = detail
        self.engine = engine
        qf = extract_queryable_fields(detail or {})
        self.rule_name = qf["rule_name"]
        self.file_path = qf["file_path"]


# ---------------------------------------------------------------------------
# Storage: _finding_to_code_scanning_dict round-trips engine + dataflowTrace
# ---------------------------------------------------------------------------

def test_storage_exposes_engine_column_and_dataflow_trace():
    dataflow = [
        {"file": "src/app.py", "line": 10, "snippet": "q = request.args['q']", "role": "source"},
        {"file": "src/app.py", "line": 42, "snippet": "cursor.execute(q)", "role": "sink"},
    ]
    detail = {
        "ruleId": "semgrep-sqli",
        "ruleName": "SQL Injection",
        "filePath": "src/app.py",
        "startLine": 42,
        "endLine": 42,
        "snippet": "cursor.execute(q)",
        "message": "tainted flow",
        "category": "security",
        "cwe": ["CWE-89"],
        "confidence": "high",
        "dataflowTrace": dataflow,
        "ruleIds": ["semgrep-sqli"],
    }
    result = _finding_to_code_scanning_dict(_MockFinding(detail, engine="semgrep"), decision=None)

    assert result["engine"] == "semgrep"
    assert result["dataflow_trace"] == dataflow
    assert result["rule_ids"] == ["semgrep-sqli"]


def test_storage_engine_defaults_to_none_when_column_missing():
    """Findings predating the engine column (no attribute) must not blow up."""

    class _LegacyFinding(_MockFinding):
        def __init__(self, detail):
            super().__init__(detail)
            # Simulate the absence of the engine attribute entirely.
            del self.engine

    result = _finding_to_code_scanning_dict(_LegacyFinding({"ruleId": "r"}), decision=None)
    assert result["engine"] is None
    assert result["dataflow_trace"] is None
    assert result["rule_ids"] is None


# ---------------------------------------------------------------------------
# GraphQL: _make_dataflow_trace + resolver wiring
# ---------------------------------------------------------------------------

def test_make_dataflow_trace_handles_empty_and_invalid_inputs():
    assert _make_dataflow_trace(None) is None
    assert _make_dataflow_trace([]) is None
    # Non-dict entries are filtered out.
    steps = _make_dataflow_trace([{"file": "a.py", "line": 1, "snippet": "x", "role": "source"}, "garbage"])
    assert steps is not None
    assert len(steps) == 1
    assert isinstance(steps[0], CodeScanningDataflowStep)


def test_make_dataflow_trace_defaults_role_to_intermediate():
    [step] = _make_dataflow_trace([{"file": "a.py", "line": 5, "snippet": "y"}])
    assert step.role == "intermediate"


def test_graphql_finding_exposes_engine_and_dataflow_trace():
    """End-to-end through the resolver: a semgrep finding with engine attribution
    and a 2-step dataflow trace produces a CodeScanningFinding with both
    surfaces populated."""
    mock_findings = [
        {
            "state": "open",
            "severity": "high",
            "rule_id": "semgrep-sqli",
            "rule_name": "SQL Injection",
            "repo_full_name": "acme-org/api",
            "file_path": "src/app.py",
            "start_line": 42,
            "engine": "semgrep",
            "rule_ids": ["semgrep-sqli"],
            "dataflow_trace": [
                {"file": "src/app.py", "line": 10, "snippet": "q = request.args['q']", "role": "source"},
                {"file": "src/app.py", "line": 42, "snippet": "cursor.execute(q)", "role": "sink"},
            ],
        }
    ]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["acme-org"], "tier": "pro", "request": None, "_cache": {}}

    with patch(
        "src.graphql.code_scanning_resolvers.read_code_scanning_findings",
        return_value=mock_findings,
    ):
        result = code_scanning_findings(
            org="acme-org", page=1, per_page=10, asset_ids=["asset-1"], info_context=ctx
        )

    assert len(result.items) == 1
    item = result.items[0]
    assert item.engine == "semgrep"
    assert item.rule_ids == ["semgrep-sqli"]
    assert item.dataflow_trace is not None
    assert len(item.dataflow_trace) == 2
    assert item.dataflow_trace[0].role == "source"
    assert item.dataflow_trace[0].line == 10
    assert item.dataflow_trace[1].role == "sink"
    assert item.dataflow_trace[1].line == 42


def test_graphql_finding_engine_fields_optional_when_missing():
    """Findings without engine attribution or a dataflow trace must still
    serialize cleanly with engine/trace as None."""
    mock_findings = [
        {
            "state": "open",
            "severity": "medium",
            "rule_id": "semgrep-xss",
            "repo_full_name": "acme-org/api",
        }
    ]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["acme-org"], "tier": "pro", "request": None, "_cache": {}}

    with patch(
        "src.graphql.code_scanning_resolvers.read_code_scanning_findings",
        return_value=mock_findings,
    ):
        result = code_scanning_findings(
            org="acme-org", page=1, per_page=10, asset_ids=["asset-1"], info_context=ctx
        )

    assert len(result.items) == 1
    item = result.items[0]
    assert item.engine is None
    assert item.dataflow_trace is None
    assert item.rule_ids is None

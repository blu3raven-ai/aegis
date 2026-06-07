"""Tests for merging opengrep + joern findings by (file, line, cwe)."""
from __future__ import annotations

from src.code_scanning.merge import merge_engine_findings


def _f(engine, file, line, cwe, severity, rule_id, dataflow=None):
    return {
        "engine": engine,
        "repo_full_name": "acme/api",
        "file_path": file,
        "start_line": line,
        "cwe": [cwe] if cwe else [],
        "severity": severity,
        "rule_id": rule_id,
        "dataflow_trace": dataflow,
    }


def test_collapses_opengrep_and_joern_same_cwe_location():
    out = merge_engine_findings([
        _f("opengrep", "app.py", 42, "CWE-89", "medium", "opengrep-sqli"),
        _f("joern", "app.py", 42, "CWE-89", "high", "joern-sqli",
           dataflow=[{"file": "app.py", "line": 40, "snippet": "id=req.args['id']", "role": "source"}]),
    ])
    assert len(out) == 1
    m = out[0]
    assert m["engine"] == "both"
    assert m["severity"] == "high"
    # rule_id becomes an engine-agnostic surrogate so the lifecycle
    # identity_key stays stable across engine-coverage changes. The
    # original per-engine rule_ids are preserved in _rule_ids ->
    # detail.ruleIds.
    assert m["rule_id"] == "sast:cwe-89"
    assert sorted(m["_rule_ids"]) == ["joern-sqli", "opengrep-sqli"]
    assert m["dataflow_trace"][0]["role"] == "source"


def test_does_not_merge_when_cwe_differs():
    out = merge_engine_findings([
        _f("opengrep", "app.py", 42, "CWE-89", "medium", "opengrep-sqli"),
        _f("joern", "app.py", 42, "CWE-78", "high", "joern-cmdi"),
    ])
    assert len(out) == 2


def test_does_not_merge_when_line_differs():
    out = merge_engine_findings([
        _f("opengrep", "app.py", 42, "CWE-89", "medium", "opengrep-sqli"),
        _f("joern", "app.py", 100, "CWE-89", "high", "joern-sqli"),
    ])
    assert len(out) == 2


def test_dataflow_trace_persists():
    trace = [{"file": "a.py", "line": 1, "snippet": "x", "role": "source"}]
    out = merge_engine_findings([_f("joern", "a.py", 5, "CWE-22", "high", "joern-path", dataflow=trace)])
    assert out[0]["dataflow_trace"] == trace


def test_legacy_finding_missing_engine_defaults_to_opengrep_behaviour():
    # Default behaviour: a single finding without an `engine` key passes
    # through unchanged.
    f = _f("", "app.py", 1, "CWE-89", "medium", "opengrep-sqli")
    del f["engine"]
    out = merge_engine_findings([f])
    assert len(out) == 1
    # engine stays absent / falsy — merge doesn't invent one
    assert not out[0].get("engine")


def test_severity_max_picks_higher():
    out = merge_engine_findings([
        _f("opengrep", "a.py", 1, "CWE-89", "low", "og"),
        _f("joern", "a.py", 1, "CWE-89", "critical", "jn"),
    ])
    assert out[0]["severity"] == "critical"


def test_three_way_same_cwe_collapses_to_one():
    # If somehow we had three engines tagging the same loc, still collapses.
    out = merge_engine_findings([
        _f("opengrep", "a.py", 1, "CWE-89", "low", "og"),
        _f("joern", "a.py", 1, "CWE-89", "medium", "jn"),
        _f("opengrep", "a.py", 1, "CWE-89", "high", "og2"),
    ])
    assert len(out) == 1
    assert out[0]["severity"] == "high"


def test_merge_result_is_order_invariant():
    """Merging [opengrep, joern] and [joern, opengrep] should produce
    equivalent merged findings (modulo first-seen rule_id)."""
    a = merge_engine_findings([
        _f("opengrep", "app.py", 42, "CWE-89", "medium", "opengrep-sqli"),
        _f("joern", "app.py", 42, "CWE-89", "high", "joern-sqli",
           dataflow=[{"file": "app.py", "line": 40, "snippet": "x", "role": "source"}]),
    ])
    b = merge_engine_findings([
        _f("joern", "app.py", 42, "CWE-89", "high", "joern-sqli",
           dataflow=[{"file": "app.py", "line": 40, "snippet": "x", "role": "source"}]),
        _f("opengrep", "app.py", 42, "CWE-89", "medium", "opengrep-sqli"),
    ])
    assert len(a) == 1 and len(b) == 1
    # rule_id depends on first-seen, which is the documented behaviour
    assert sorted(a[0]["_rule_ids"]) == sorted(b[0]["_rule_ids"])
    # All order-invariant fields:
    assert a[0]["severity"] == b[0]["severity"] == "high"
    assert a[0]["engine"] == b[0]["engine"] == "both"
    assert a[0]["dataflow_trace"] == b[0]["dataflow_trace"]
    assert a[0]["cwe"] == b[0]["cwe"]

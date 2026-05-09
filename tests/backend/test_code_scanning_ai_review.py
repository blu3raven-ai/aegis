"""Tests for redesigned code scanning AI reviewer: tiering, CWE resolver, prompt, schema."""
import json
import pytest
from src.code_scanning.ai_review import (
    _get_tier,
    _resolve_cwe_group,
    _prompt,
    _schema,
    _validate_review,
    CodeScanningAiReviewError,
)


# --- Tiering ---

def test_tier_critical_is_deep():
    assert _get_tier({"severity": "critical"}) == "deep"


def test_tier_high_is_deep():
    assert _get_tier({"severity": "high"}) == "deep"


def test_tier_medium_is_light():
    assert _get_tier({"severity": "medium"}) == "light"


def test_tier_low_is_skip():
    assert _get_tier({"severity": "low"}) == "skip"


def test_tier_unknown_is_skip():
    assert _get_tier({"severity": "unknown"}) == "skip"


# --- CWE group resolver ---

def test_cwe_resolver_sqli():
    group = _resolve_cwe_group(["CWE-89"])
    assert group["name"] == "Injection"
    assert any("parameterized" in q for q in group["questions"])


def test_cwe_resolver_xss():
    group = _resolve_cwe_group(["CWE-79"])
    assert group["name"] == "Cross-Site Scripting (XSS)"


def test_cwe_resolver_path():
    group = _resolve_cwe_group(["CWE-22"])
    assert "Path" in group["name"]


def test_cwe_resolver_ssrf():
    group = _resolve_cwe_group(["CWE-918"])
    assert "SSRF" in group["name"]


def test_cwe_resolver_auth():
    group = _resolve_cwe_group(["CWE-798"])
    assert "Auth" in group["name"] or "Crypto" in group["name"]


def test_cwe_resolver_unknown_falls_back_to_generic():
    group = _resolve_cwe_group(["CWE-9999"])
    assert group["name"] == "Security Finding"


def test_cwe_resolver_empty_falls_back_to_generic():
    group = _resolve_cwe_group([])
    assert group["name"] == "Security Finding"


def test_all_groups_have_path_feasibility_question():
    """Every CWE group checklist must end with the path feasibility question."""
    from src.code_scanning.ai_review import _CWE_GROUPS
    for group_key, group in _CWE_GROUPS.items():
        last = group["questions"][-1]
        assert "reachable" in last.lower(), f"Group '{group_key}' missing path feasibility question"


# --- Prompt structure ---

def _sample_finding(severity="high", cwe=None, file_class="source"):
    return {
        "rule_id": "python.sqli",
        "rule_name": "SQL Injection",
        "severity": severity,
        "message": "SQL injection via user input",
        "file_path": "src/app.py",
        "start_line": 10,
        "snippet": "cursor.execute(query)",
        "fix_suggestion": None,
        "cwe": cwe or ["CWE-89"],
        "category": "security",
        "file_class": file_class,
        "language": "python",
        "code_flows": [
            {"file": "src/app.py", "line": 5, "snippet": "query = request.args.get('id')"},
            {"file": "src/app.py", "line": 10, "snippet": "cursor.execute(query)"},
        ],
        "code_window": "def handler():\n    query = request.args.get('id')\n    cursor.execute(query)",
        "imports": "import flask",
    }


def test_deep_prompt_includes_code_flows():
    payload = json.loads(_prompt(_sample_finding(severity="high"), tier="deep"))
    assert "code_flows" in payload["finding"]
    assert len(payload["finding"]["code_flows"]) == 2


def test_deep_prompt_includes_code_window():
    payload = json.loads(_prompt(_sample_finding(severity="high"), tier="deep"))
    assert "code_window" in payload["finding"]
    assert "handler" in payload["finding"]["code_window"]


def test_deep_prompt_includes_imports():
    payload = json.loads(_prompt(_sample_finding(severity="high"), tier="deep"))
    assert "imports" in payload["finding"]


def test_light_prompt_omits_code_window():
    payload = json.loads(_prompt(_sample_finding(severity="medium"), tier="light"))
    assert "code_window" not in payload["finding"]
    assert "code_flows" not in payload["finding"]


def test_prompt_includes_language():
    payload = json.loads(_prompt(_sample_finding(), tier="deep"))
    assert payload["language"] == "python"


def test_prompt_includes_checklist():
    payload = json.loads(_prompt(_sample_finding(), tier="deep"))
    assert "checklist" in payload
    assert len(payload["checklist"]) >= 3


def test_prompt_includes_vulnerability_class():
    payload = json.loads(_prompt(_sample_finding(cwe=["CWE-89"]), tier="deep"))
    assert "Injection" in payload["vulnerability_class"]
    assert "CWE-89" in payload["vulnerability_class"]


# --- Schema ---

def test_schema_requires_reasoning():
    schema = _schema()
    assert "reasoning" in schema["required"]
    assert "reasoning" in schema["properties"]


# --- validate_review ---

def test_validate_review_accepts_reasoning():
    result = _validate_review({
        "reasoning": "Step 1: user-controlled. Step 2: no escaping.",
        "verdict": "true_positive",
        "explanation": "Direct taint flow.",
        "confidence": "high",
    })
    assert result["reasoning"] == "Step 1: user-controlled. Step 2: no escaping."
    assert result["verdict"] == "true_positive"


def test_validate_review_empty_reasoning_is_ok():
    result = _validate_review({
        "reasoning": "",
        "verdict": "needs_review",
        "explanation": "Unclear.",
        "confidence": "medium",
    })
    assert result["reasoning"] == ""


def test_validate_review_rejects_bad_verdict():
    with pytest.raises(CodeScanningAiReviewError, match="unsupported verdict"):
        _validate_review({
            "reasoning": "",
            "verdict": "maybe",
            "explanation": "x",
            "confidence": "low",
        })

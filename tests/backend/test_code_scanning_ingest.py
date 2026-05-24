"""Tests for code scanning ingest new fields: code_flows, code_window, imports, file_class, language."""
import json
import pytest
from pathlib import Path
from src.code_scanning.ingest import ingest_findings_jsonl, _derive_language


def test_derive_language_python():
    assert _derive_language("src/app.py") == "python"


def test_derive_language_typescript():
    assert _derive_language("src/utils/helper.tsx") == "typescript"


def test_derive_language_go():
    assert _derive_language("cmd/server/main.go") == "go"


def test_derive_language_unknown():
    assert _derive_language("Makefile") == "unknown"


def test_derive_language_no_extension():
    assert _derive_language("Dockerfile") == "unknown"


def test_ingest_passes_through_code_flows(tmp_path):
    finding = {
        "repo_full_name": "org/repo",
        "file_path": "src/app.py",
        "start_line": 10,
        "end_line": 10,
        "rule_id": "python.sqli",
        "rule_name": "SQL Injection",
        "severity": "high",
        "confidence": "high",
        "category": "security",
        "cwe": ["CWE-89"],
        "message": "SQL injection",
        "snippet": "cursor.execute(q)",
        "fix_suggestion": None,
        "stateCandidate": "open",
        "code_flows": [
            {"file": "src/app.py", "line": 5, "snippet": "q = request.args.get('id')"},
            {"file": "src/app.py", "line": 10, "snippet": "cursor.execute(q)"},
        ],
        "code_window": "def handler():\n    q = request.args.get('id')\n    cursor.execute(q)",
        "imports": "import flask\nfrom flask import request",
        "file_class": "source",
    }
    p = tmp_path / "findings.jsonl"
    p.write_text(json.dumps(finding) + "\n")

    findings = ingest_findings_jsonl(p)
    assert len(findings) == 1
    f = findings[0]
    assert f["code_flows"] == finding["code_flows"]
    assert f["code_window"] == finding["code_window"]
    assert f["imports"] == finding["imports"]
    assert f["file_class"] == "source"
    assert f["language"] == "python"


def test_ingest_missing_new_fields_defaults(tmp_path):
    """Old-format findings (no new fields) get safe defaults."""
    finding = {
        "repo_full_name": "org/repo",
        "file_path": "src/App.java",
        "start_line": 1,
        "end_line": 1,
        "rule_id": "java.sqli",
        "rule_name": "SQL Injection",
        "severity": "critical",
        "confidence": "high",
        "category": "security",
        "cwe": [],
        "message": "msg",
        "snippet": "stmt.execute(q)",
        "stateCandidate": "open",
    }
    p = tmp_path / "findings.jsonl"
    p.write_text(json.dumps(finding) + "\n")

    findings = ingest_findings_jsonl(p)
    assert len(findings) == 1
    f = findings[0]
    assert f["code_flows"] == []
    assert f["code_window"] == ""
    assert f["imports"] == ""
    assert f["file_class"] == "source"
    assert f["language"] == "java"


def test_ingest_passes_through_repo_html_url(tmp_path):
    """repo_html_url from the scanner is preserved through ingestion."""
    finding = {
        "repo_full_name": "acme-org/example-repo",
        "repo_html_url": "https://github.com/acme-org/example-repo",
        "file_path": "src/app.py",
        "start_line": 10,
        "end_line": 10,
        "rule_id": "python.injection",
        "rule_name": "Injection",
        "severity": "high",
        "confidence": "high",
        "category": "security",
        "cwe": ["CWE-78"],
        "message": "Dangerous call",
        "snippet": "subprocess.run(cmd)",
        "stateCandidate": "open",
    }
    p = tmp_path / "findings.jsonl"
    p.write_text(json.dumps(finding) + "\n")

    findings = ingest_findings_jsonl(p)
    assert len(findings) == 1
    assert findings[0]["repo_html_url"] == "https://github.com/acme-org/example-repo"


def test_ingest_repo_html_url_absent_when_not_in_jsonl(tmp_path):
    """When scanner did not write html_url.txt, repo_html_url is empty string."""
    finding = {
        "repo_full_name": "acme-org/example-repo",
        "file_path": "src/app.py",
        "start_line": 10,
        "end_line": 10,
        "rule_id": "python.injection",
        "rule_name": "Injection",
        "severity": "high",
        "confidence": "high",
        "category": "security",
        "cwe": [],
        "message": "Dangerous call",
        "snippet": "subprocess.run(cmd)",
        "stateCandidate": "open",
    }
    p = tmp_path / "findings.jsonl"
    p.write_text(json.dumps(finding) + "\n")

    findings = ingest_findings_jsonl(p)
    assert len(findings) == 1
    assert findings[0]["repo_html_url"] == ""

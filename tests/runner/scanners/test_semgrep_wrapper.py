"""Semgrep wrapper tests - parsing + finding shape."""
from __future__ import annotations

from runner.scanners.code_scanning.semgrep import parse_semgrep_results


def test_parses_results_into_findings():
    raw = {
        "results": [
            {
                "check_id": "python.flask.security.injection.tainted-sql-string",
                "path": "src/api.py",
                "start": {"line": 42, "col": 1},
                "end": {"line": 42, "col": 80},
                "extra": {
                    "message": "Possible SQL injection",
                    "severity": "ERROR",
                    "lines": "query = f\"SELECT * FROM t WHERE id = {request.args['id']}\"",
                    "metadata": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]},
                },
            },
            {
                "check_id": "javascript.express.security.audit.xss-direct-response",
                "path": "src/server.js",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 50},
                "extra": {
                    "message": "Possible XSS",
                    "severity": "WARNING",
                    "lines": "res.send(req.query.html)",
                    "metadata": {},
                },
            },
        ],
    }
    findings = parse_semgrep_results(raw, repo_root="/")
    assert len(findings) == 2
    sqli = findings[0]
    assert sqli["tool"] == "code_scanning"
    assert sqli["rule"] == "python.flask.security.injection.tainted-sql-string"
    assert sqli["severity"] == "high"
    assert sqli["file"] == "src/api.py"
    assert sqli["line"] == 42
    assert "SELECT" in sqli["snippet"]
    assert sqli["fingerprint"]
    xss = findings[1]
    assert xss["severity"] == "medium"


def test_severity_mapping_handles_all_levels():
    cases = [("ERROR", "high"), ("WARNING", "medium"), ("INFO", "low"), ("", "medium")]
    for sev_in, sev_expected in cases:
        raw = {"results": [{
            "check_id": "x", "path": "/a.py",
            "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 5},
            "extra": {"message": "m", "severity": sev_in, "lines": "x", "metadata": {}},
        }]}
        findings = parse_semgrep_results(raw, repo_root="/")
        assert findings[0]["severity"] == sev_expected, f"sev {sev_in}"


def test_empty_results_returns_empty_list():
    assert parse_semgrep_results({"results": []}, repo_root="/") == []


def test_path_normalized_relative_to_repo_root():
    raw = {"results": [{
        "check_id": "x", "path": "/work/repo/src/api.py",
        "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 5},
        "extra": {"message": "m", "severity": "ERROR", "lines": "x", "metadata": {}},
    }]}
    findings = parse_semgrep_results(raw, repo_root="/work/repo")
    assert findings[0]["file"] == "src/api.py"


def test_run_semgrep_sarif_writes_sarif_output(tmp_path):
    """run_semgrep_sarif builds the right CLI args and returns the sarif path."""
    from unittest.mock import patch, MagicMock

    from runner.scanners.code_scanning import semgrep

    sarif_out = tmp_path / "semgrep.sarif"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        sarif_out.write_text('{"$schema":"sarif-2.1.0","runs":[]}')
        result = semgrep.run_semgrep_sarif(str(tmp_path), sarif_out)

    assert result == sarif_out
    args = mock_run.call_args[0][0]
    assert "--sarif" in args
    assert "-o" in args
    assert str(sarif_out) in args
    assert "--json" not in args


def test_run_semgrep_sarif_returns_none_on_missing_output(tmp_path):
    """When semgrep exits but writes no SARIF, return None."""
    from unittest.mock import patch, MagicMock

    from runner.scanners.code_scanning import semgrep

    sarif_out = tmp_path / "absent.sarif"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="bad config")
        result = semgrep.run_semgrep_sarif(str(tmp_path), sarif_out)

    assert result is None

"""Tests for Joern finding normalization into the unified findings.jsonl."""
from __future__ import annotations

import json
from pathlib import Path


def _write_joern_payload(repo_dir: Path, findings: list[dict]) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "joern_findings.json").write_text(
        json.dumps({"status": "ok", "findings": findings})
    )


def test_normalize_joern_finding_appears_in_findings_jsonl(tmp_path):
    from runner.scanners.code_scanning.normalize import (
        normalize_code_scanning_output,
    )

    repo = tmp_path / "repo-a"
    repo.mkdir()
    (repo / "head-sha.txt").write_text("deadbeef\n")
    (repo / "html_url.txt").write_text("https://github.com/acme/repo-a\n")
    _write_joern_payload(
        repo,
        [
            {
                "engine": "joern",
                "cwe": "CWE-89",
                "file": "src/app.py",
                "line": 42,
                "rule_id": "joern.sqli",
                "severity": "high",
                "title": "SQL injection via concatenation",
                "dataflow_trace": [
                    {"file": "src/app.py", "line": 10, "snippet": "req.args"},
                    {"file": "src/app.py", "line": 42, "snippet": "cursor.execute(q)"},
                ],
            }
        ],
    )

    total, errors = normalize_code_scanning_output("acme", tmp_path, "run-1")

    assert errors == 0
    assert total == 1
    lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])

    assert record["engine"] == "joern"
    assert record["dataflow_trace"][0]["line"] == 10
    assert record["dataflow_trace"][-1]["line"] == 42
    assert record["file_path"] == "src/app.py"
    assert record["start_line"] == 42
    assert record["end_line"] == 42
    assert record["rule_id"] == "joern.sqli"
    assert record["rule_name"] == "SQL injection via concatenation"
    assert record["cwe"] == ["CWE-89"]
    assert isinstance(record["cwe"], list)
    assert record["repo_full_name"] == "repo-a"
    assert record["commit_sha"] == "deadbeef"
    assert record["repo_html_url"] == "https://github.com/acme/repo-a"
    assert record["confidence"] == "high"
    assert record["category"] == "security"
    assert record["stateCandidate"] == "open"
    assert record["file_class"] == "source"


def test_normalize_joern_filters_vendor_and_generated(tmp_path):
    from runner.scanners.code_scanning.normalize import (
        normalize_code_scanning_output,
    )

    repo = tmp_path / "repo-b"
    repo.mkdir()
    (repo / "context.json").write_text(
        json.dumps(
            {
                "node_modules/lib/index.js:1": {"file_class": "vendor"},
                "dist/bundle.min.js:2": {"file_class": "generated"},
                "src/keep.py:3": {"file_class": "source"},
            }
        )
    )
    _write_joern_payload(
        repo,
        [
            {
                "cwe": "CWE-78",
                "file": "node_modules/lib/index.js",
                "line": 1,
                "rule_id": "joern.cmd-injection",
                "severity": "high",
                "title": "Command injection in vendor dep",
                "dataflow_trace": [],
            },
            {
                "cwe": "CWE-78",
                "file": "dist/bundle.min.js",
                "line": 2,
                "rule_id": "joern.cmd-injection",
                "severity": "high",
                "title": "Command injection in generated bundle",
                "dataflow_trace": [],
            },
            {
                "cwe": "CWE-22",
                "file": "src/keep.py",
                "line": 3,
                "rule_id": "joern.path-traversal",
                "severity": "high",
                "title": "Path traversal",
                "dataflow_trace": [],
            },
        ],
    )

    total, errors = normalize_code_scanning_output("acme", tmp_path, "run-1")

    assert errors == 0
    assert total == 1
    lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["file_path"] == "src/keep.py"
    assert record["file_class"] == "source"


def test_normalize_joern_and_opengrep_share_findings_jsonl(tmp_path):
    """Both engines should write into the same findings.jsonl in one pass."""
    from runner.scanners.code_scanning.normalize import (
        normalize_code_scanning_output,
    )

    repo = tmp_path / "repo-c"
    repo.mkdir()
    (repo / "opengrep.json").write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "og.rule"}]}},
                        "results": [
                            {
                                "ruleId": "og.rule",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "a.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )
    _write_joern_payload(
        repo,
        [
            {
                "cwe": "CWE-918",
                "file": "b.py",
                "line": 7,
                "rule_id": "joern.ssrf",
                "severity": "high",
                "title": "SSRF",
                "dataflow_trace": [],
            }
        ],
    )

    total, errors = normalize_code_scanning_output("acme", tmp_path, "run-1")

    assert errors == 0
    assert total == 2
    records = [
        json.loads(line)
        for line in (tmp_path / "findings.jsonl").read_text().splitlines()
    ]
    for r in records:
        assert "engine" in r
    engines = sorted(r["engine"] for r in records)
    assert engines == ["joern", "opengrep"]


def test_normalize_joern_bad_entry_skips_itself_not_batch(tmp_path, caplog):
    """A single malformed joern entry must not drop the whole repo's findings."""
    from runner.scanners.code_scanning.normalize import (
        normalize_code_scanning_output,
    )

    repo = tmp_path / "repo-d"
    repo.mkdir()
    _write_joern_payload(
        repo,
        [
            {
                "cwe": "CWE-89",
                "file": "src/good.py",
                "line": 5,
                "rule_id": "joern.sqli",
                "severity": "high",
                "title": "Good finding",
                "dataflow_trace": [],
            },
            {
                "cwe": "CWE-89",
                "file": "src/bad.py",
                "line": "not-a-number",
                "rule_id": "joern.sqli",
                "severity": "high",
                "title": "Bad finding",
                "dataflow_trace": [],
            },
        ],
    )

    with caplog.at_level("WARNING"):
        total, errors = normalize_code_scanning_output("acme", tmp_path, "run-1")

    assert total == 1
    assert errors == 1
    lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["file_path"] == "src/good.py"
    assert record["engine"] == "joern"

    assert any("Failed joern entry" in m for m in caplog.messages)

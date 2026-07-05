"""Code scanning normalize: post-engine-swap walks semgrep.sarif."""
from __future__ import annotations

import json

from runner.scanners.code_scanning import normalize


def test_normalize_walks_semgrep_sarif(tmp_path):
    repo_out = tmp_path / "acme-org" / "svc"
    repo_out.mkdir(parents=True)
    (repo_out / "head-sha.txt").write_text("abc123")
    sarif_payload = {
        "runs": [{
            "tool": {"driver": {"rules": [{
                "id": "python.security.eval",
                "shortDescription": {"text": "Use of eval"},
                "defaultConfiguration": {"level": "error"},
                "properties": {"precision": "high", "tags": ["CWE-94"]},
            }]}},
            "results": [{
                "ruleId": "python.security.eval",
                "level": "error",
                "message": {"text": "eval(user_input)"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 10, "endLine": 10},
                    }
                }],
            }],
        }]
    }
    (repo_out / "semgrep.sarif").write_text(json.dumps(sarif_payload))

    total, errors = normalize.normalize_code_scanning_output("acme-org", tmp_path, "run-1")

    assert total == 1
    assert errors == 0
    findings = [json.loads(l) for l in (tmp_path / "findings.jsonl").read_text().splitlines()]
    assert findings[0]["engine"] == "semgrep"
    assert findings[0]["rule_id"] == "python.security.eval"
    assert findings[0]["file_path"] == "app.py"


def test_normalize_ignores_legacy_opengrep_json(tmp_path):
    """After the swap, opengrep.json files are no longer walked."""
    repo_out = tmp_path / "acme-org" / "svc"
    repo_out.mkdir(parents=True)
    (repo_out / "head-sha.txt").write_text("abc123")
    # An old opengrep.json file should produce zero findings now.
    (repo_out / "opengrep.json").write_text(json.dumps({"runs": []}))

    total, errors = normalize.normalize_code_scanning_output("acme-org", tmp_path, "run-1")
    assert total == 0
    assert errors == 0

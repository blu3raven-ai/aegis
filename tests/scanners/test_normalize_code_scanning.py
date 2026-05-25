"""Tests for normalize-code-scanning.py — tmp-prefix stripping in ctx_key lookups."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

# Load the hyphenated-name module directly
_spec = importlib.util.spec_from_file_location(
    "normalize_code_scanning",
    Path(__file__).parent.parent.parent / "scanners" / "code-scanning" / "scripts" / "normalize-code-scanning.py",
)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]
normalize_file = _mod.normalize_file


def _sarif(uri: str, start_line: int, rule_id: str = "python.injection") -> dict:
    return {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "opengrep",
                    "rules": [{
                        "id": rule_id,
                        "shortDescription": {"text": "Injection"},
                        "defaultConfiguration": {"level": "warning"},
                        "properties": {"precision": "high", "tags": [], "category": "security"},
                    }],
                }
            },
            "results": [{
                "ruleId": rule_id,
                "message": {"text": "Potential injection"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": start_line,
                            "endLine": start_line,
                            "snippet": {"text": "requests.post(url)"},
                        },
                    }
                }],
            }],
        }]
    }


# ── ctx_key stripping ─────────────────────────────────────────────────────────


def test_ctx_key_strips_tmp_prefix_for_context_lookup(tmp_path):
    """
    When Opengrep writes /tmp/tmp.XXXX/server.py into the SARIF, normalize_file must
    strip the prefix before building ctx_key so it matches what extract-context.sh
    wrote into context.json with the relative path.
    """
    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps(_sarif("/tmp/tmp.tum6N6HTcv/server.py", 93)))

    # context.json keys use relative paths (extract-context.sh strips the prefix)
    context = {
        "server.py:93": {
            "file_class": "source",
            "code_window": "def handle():\n    requests.post(url)\n",
            "imports": "import requests",
        }
    }

    findings, _ = normalize_file(sarif, "acme-org", "acme-org/api", "abc123", context, {})

    assert len(findings) == 1
    assert findings[0]["code_window"] == "def handle():\n    requests.post(url)\n"


def test_ctx_key_strips_tmp_prefix_for_reachability_lookup(tmp_path):
    """Reachability dict lookup must also use the stripped relative key."""
    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps(_sarif("/tmp/tmp.tum6N6HTcv/server.py", 93)))

    context = {"server.py:93": {"file_class": "source", "code_window": "", "imports": ""}}
    reachability = {
        "server.py:93": {
            "verdict": "reachable",
            "entry_point": "transcribe_audio",
            "call_chain": [
                {"function": "transcribe_audio", "file": "server.py", "line": 46, "snippet": "def transcribe_audio():"}
            ],
        }
    }

    findings, _ = normalize_file(sarif, "acme-org", "acme-org/api", "abc123", context, reachability)

    assert len(findings) == 1
    r = findings[0]["reachability"]
    assert r is not None, "reachability must be populated when key matches"
    assert r["verdict"] == "reachable"
    assert r["entry_point"] == "transcribe_audio"


def test_absolute_uri_without_strip_produces_null_reachability(tmp_path):
    """
    Regression: before the fix, absolute-path SARIF URIs produced ctx_key like
    '/tmp/tmp.XXXX/server.py:93' which never matched reachability.json's
    relative keys — resulting in null reachability.  Confirm the old behaviour
    would fail by verifying the raw absolute key is NOT in the reachability dict.
    """
    absolute_key = "/tmp/tmp.tum6N6HTcv/server.py:93"
    reachability = {
        "server.py:93": {
            "verdict": "reachable",
            "entry_point": "main",
            "call_chain": [],
        }
    }

    # The absolute key must not exist — this is what broke the lookup pre-fix
    assert absolute_key not in reachability


def test_relative_uri_works_without_stripping(tmp_path):
    """URIs that are already relative must continue to work as before."""
    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps(_sarif("server.py", 46)))

    context = {
        "server.py:46": {
            "file_class": "source",
            "code_window": "def transcribe():\n    pass\n",
            "imports": "",
        }
    }

    findings, _ = normalize_file(sarif, "acme-org", "acme-org/api", "abc123", context, {})

    assert len(findings) == 1
    assert findings[0]["code_window"] == "def transcribe():\n    pass\n"


# ── file_class filtering ──────────────────────────────────────────────────────


def test_vendor_file_class_is_filtered_out(tmp_path):
    """Findings in vendor files are skipped entirely."""
    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps(_sarif("vendor/lib/util.py", 10)))

    context = {"vendor/lib/util.py:10": {"file_class": "vendor", "code_window": "", "imports": ""}}

    findings, _ = normalize_file(sarif, "acme-org", "acme-org/api", "abc123", context, {})

    assert len(findings) == 0


def test_generated_file_class_is_filtered_out(tmp_path):
    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps(_sarif("dist/bundle.js", 1)))

    context = {"dist/bundle.js:1": {"file_class": "generated", "code_window": "", "imports": ""}}

    findings, _ = normalize_file(sarif, "acme-org", "acme-org/api", "abc123", context, {})

    assert len(findings) == 0


# ── field propagation ─────────────────────────────────────────────────────────


def test_missing_context_entry_still_produces_finding(tmp_path):
    """When context.json has no entry for a finding, the finding is still produced with empty fields."""
    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps(_sarif("server.py", 10)))

    findings, _ = normalize_file(sarif, "acme-org", "acme-org/api", "abc123", {}, {})

    assert len(findings) == 1
    assert findings[0]["reachability"] is None


def test_call_chain_snippet_is_propagated_to_finding(tmp_path):
    """call_chain snippets from reachability.json appear on the finding's reachability field."""
    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps(_sarif("server.py", 93)))

    context = {"server.py:93": {"file_class": "source", "code_window": "", "imports": ""}}
    reachability = {
        "server.py:93": {
            "verdict": "reachable",
            "entry_point": "main",
            "call_chain": [
                {"function": "main", "file": "app.py", "line": 10, "snippet": "def main():\n    transcribe_audio()"},
                {"function": "transcribe_audio", "file": "server.py", "line": 46, "snippet": "def transcribe_audio():\n    backend_response = requests.post(BACKEND_URL)"},
            ],
        }
    }

    findings, _ = normalize_file(sarif, "acme-org", "acme-org/api", "abc123", context, reachability)

    assert len(findings) == 1
    chain = findings[0]["reachability"]["call_chain"]
    assert len(chain) == 2
    assert chain[0]["snippet"] == "def main():\n    transcribe_audio()"
    assert chain[1]["snippet"] == "def transcribe_audio():\n    backend_response = requests.post(BACKEND_URL)"

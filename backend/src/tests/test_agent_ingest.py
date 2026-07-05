"""Agent-scanning ingest: lifecycle hooks, detail mapping, and jsonl parsing.

The runner emits normalized agent-security findings to MinIO; the backend
ingests them through the shared lifecycle (tool="agent_scanning"). Identity is
line-independent so an edit that shifts a finding's line keeps its triage state.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.agent_scanning.ingest import read_agent_findings  # noqa: E402
from src.agent_scanning.lifecycle import agent_scanning_hooks  # noqa: E402
from src.shared.finding_detail_blob import split_detail  # noqa: E402
from src.shared.finding_queryable_fields import extract_queryable_fields  # noqa: E402
from src.shared.lifecycle import ScanContext  # noqa: E402


def _raw(line: int, *, check="AGENT_INVISIBLE_UNICODE", resource="U+E0001", file="CLAUDE.md"):
    return {
        "tool": "agent_scanning",
        "check_id": check,
        "title": "Invisible unicode instruction hidden in agent rules file",
        "severity": "critical",
        "file": file,
        "line": line,
        "resource": resource,
        "guideline": "https://docs.example/agent-invisible-unicode",
        "fingerprint": "abc123",
        "repo_full_name": "acme/app",
    }


def test_identity_stable_across_line_drift():
    a = agent_scanning_hooks.compute_identity_key(_raw(12))
    b = agent_scanning_hooks.compute_identity_key(_raw(58))  # shifted by an edit above
    assert a == b


def test_identity_distinguishes_resource_and_check():
    base = agent_scanning_hooks.compute_identity_key(_raw(12))
    other_resource = agent_scanning_hooks.compute_identity_key(_raw(12, resource="U+202E"))
    other_check = agent_scanning_hooks.compute_identity_key(_raw(12, check="AGENT_AUTO_APPROVE"))
    assert base != other_resource
    assert base != other_check


def test_extract_detail_and_queryable_fields():
    detail = agent_scanning_hooks.extract_detail(_raw(12))
    assert detail["checkId"] == "AGENT_INVISIBLE_UNICODE"
    assert detail["resource"] == "U+E0001"
    q = extract_queryable_fields(detail)
    assert q["rule_name"] == "AGENT_INVISIBLE_UNICODE"
    assert q["file_path"] == "CLAUDE.md"
    assert q["title"] == "Invisible unicode instruction hidden in agent rules file"


def test_verification_fields_carried_when_present():
    raw = {**_raw(12), "verdict": "confirmed", "evidence": {"why": "smuggled instruction"}}
    detail = agent_scanning_hooks.extract_detail(raw)
    assert detail["verdict"] == "confirmed"
    assert detail["evidence"] == {"why": "smuggled instruction"}


def test_extract_detail_forwards_advisory_text():
    # The runner attaches per-rule advisory; the detail endpoint reads "message"
    # as the drawer description and "fixSuggestion" as the remediation.
    raw = {**_raw(12), "message": "Invisible tag chars smuggle instructions.", "fixSuggestion": "Delete them."}
    detail = agent_scanning_hooks.extract_detail(raw)
    assert detail["message"] == "Invisible tag chars smuggle instructions."
    assert detail["fixSuggestion"] == "Delete them."
    # Absent -> empty strings (no description/remediation rendered).
    bare = agent_scanning_hooks.extract_detail(_raw(12))
    assert bare["message"] == "" and bare["fixSuggestion"] == ""


def test_advisory_text_survives_detail_split():
    raw = {**_raw(12), "message": "why it matters", "fixSuggestion": "what to do"}
    detail = agent_scanning_hooks.extract_detail(raw)
    lean, fat = split_detail("agent_scanning", detail)
    reassembled = {**fat, **lean}
    assert reassembled["message"] == "why it matters"
    assert reassembled["fixSuggestion"] == "what to do"


def test_extract_detail_carries_repo_html_url():
    detail = agent_scanning_hooks.extract_detail(
        {**_raw(12), "repo_html_url": "https://ghe.acme-corp.internal/acme/app"}
    )
    assert detail["repoHtmlUrl"] == "https://ghe.acme-corp.internal/acme/app"
    # Absent -> empty string (renders no view-in-repo link).
    assert agent_scanning_hooks.extract_detail(_raw(12))["repoHtmlUrl"] == ""


def test_detail_splits_lean_queryable_vs_blob():
    detail = agent_scanning_hooks.extract_detail({**_raw(12), "verdict": "confirmed"})
    lean, fat = split_detail("agent_scanning", detail)
    assert lean["checkId"] == "AGENT_INVISIBLE_UNICODE"
    assert lean["resource"] == "U+E0001"
    # verification + title go to the fat blob, not the queryable column
    assert "verdict" not in lean and fat.get("verdict") == "confirmed"


def test_canonical_external_ref_resolves_repo():
    ctx = ScanContext(tool="agent_scanning", org="acme", run_id="agent-1", source_type="github")
    assert agent_scanning_hooks.canonical_external_ref(ctx, _raw(12)) == ("github:acme/app", "repo")


def test_identity_uses_repo_so_same_finding_in_two_repos_is_distinct():
    a = agent_scanning_hooks.compute_identity_key(_raw(12))
    b = agent_scanning_hooks.compute_identity_key({**_raw(12), "repo_full_name": "acme/other"})
    assert a != b


def test_read_agent_findings_parses_jsonl(tmp_path: Path):
    p = tmp_path / "findings.jsonl"
    p.write_text(
        json.dumps(_raw(12)) + "\n"
        + "\n"  # blank line ignored
        + "{not json}\n"  # malformed line skipped
        + json.dumps({"no_check_id": True}) + "\n"  # missing check_id skipped
        + json.dumps(_raw(40, check="AGENT_AUTO_APPROVE")) + "\n"
    )
    out = read_agent_findings(p)
    assert [f["check_id"] for f in out] == ["AGENT_INVISIBLE_UNICODE", "AGENT_AUTO_APPROVE"]

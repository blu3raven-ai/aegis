"""IaC (checkov) ingest: lifecycle hooks, detail mapping, and jsonl parsing.

The runner emits normalized IaC findings to MinIO; the backend ingests them
through the shared lifecycle (tool="iac_scanning"). Identity is line-independent
so an edit that shifts a finding's line keeps its triage state.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.iac.ingest import read_iac_findings  # noqa: E402
from src.iac.lifecycle import iac_scanning_hooks  # noqa: E402
from src.shared.finding_detail_blob import split_detail  # noqa: E402
from src.shared.finding_queryable_fields import extract_queryable_fields  # noqa: E402
from src.shared.lifecycle import ScanContext  # noqa: E402


def _raw(line: int, *, check="CKV_AWS_18", resource="aws_s3_bucket.logs", file="infra/s3.tf"):
    return {
        "tool": "iac_scanning",
        "check_id": check,
        "title": "Ensure S3 bucket has access logging",
        "severity": "high",
        "file": file,
        "line": line,
        "resource": resource,
        "guideline": "https://docs.example/ckv-aws-18",
        "fingerprint": "abc123",
        "repo_full_name": "acme/app",
    }


def test_identity_stable_across_line_drift():
    a = iac_scanning_hooks.compute_identity_key(_raw(12))
    b = iac_scanning_hooks.compute_identity_key(_raw(58))  # shifted by an edit above
    assert a == b


def test_identity_distinguishes_resource_and_check():
    base = iac_scanning_hooks.compute_identity_key(_raw(12))
    other_resource = iac_scanning_hooks.compute_identity_key(_raw(12, resource="aws_s3_bucket.data"))
    other_check = iac_scanning_hooks.compute_identity_key(_raw(12, check="CKV_AWS_21"))
    assert base != other_resource
    assert base != other_check


def test_extract_detail_and_queryable_fields():
    detail = iac_scanning_hooks.extract_detail(_raw(12))
    assert detail["checkId"] == "CKV_AWS_18"
    assert detail["resource"] == "aws_s3_bucket.logs"
    # the typed columns must populate from the detail
    q = extract_queryable_fields(detail)
    assert q["rule_name"] == "CKV_AWS_18"
    assert q["file_path"] == "infra/s3.tf"
    assert q["title"] == "Ensure S3 bucket has access logging"


def test_verification_fields_carried_when_present():
    raw = {**_raw(12), "verdict": "confirmed", "evidence": {"why": "public"}}
    detail = iac_scanning_hooks.extract_detail(raw)
    assert detail["verdict"] == "confirmed"
    assert detail["evidence"] == {"why": "public"}


def test_detail_splits_lean_queryable_vs_blob():
    detail = iac_scanning_hooks.extract_detail({**_raw(12), "verdict": "confirmed"})
    lean, fat = split_detail("iac_scanning", detail)
    assert lean["checkId"] == "CKV_AWS_18"
    assert lean["resource"] == "aws_s3_bucket.logs"
    # verification + title go to the fat blob, not the queryable column
    assert "verdict" not in lean and fat.get("verdict") == "confirmed"


def test_canonical_external_ref_resolves_repo():
    ctx = ScanContext(tool="iac_scanning", org="acme", run_id="iac-1", source_type="github")
    assert iac_scanning_hooks.canonical_external_ref(ctx, _raw(12)) == ("github:acme/app", "repo")


def test_identity_uses_repo_so_same_finding_in_two_repos_is_distinct():
    a = iac_scanning_hooks.compute_identity_key(_raw(12))
    b = iac_scanning_hooks.compute_identity_key({**_raw(12), "repo_full_name": "acme/other"})
    assert a != b


def test_read_iac_findings_parses_jsonl(tmp_path: Path):
    p = tmp_path / "findings.jsonl"
    p.write_text(
        json.dumps(_raw(12)) + "\n"
        + "\n"  # blank line ignored
        + "{not json}\n"  # malformed line skipped
        + json.dumps({"no_check_id": True}) + "\n"  # missing check_id skipped
        + json.dumps(_raw(40, check="CKV_AWS_21")) + "\n"
    )
    out = read_iac_findings(p)
    assert [f["check_id"] for f in out] == ["CKV_AWS_18", "CKV_AWS_21"]

"""Tests for parsing checkov JSON output."""
from __future__ import annotations

from runner.scanners.iac.parse import parse_checkov_results


def test_parses_failed_checks_into_findings():
    raw = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_19",
                    "check_name": "Encrypt S3",
                    "file_path": "/tf/s3.tf",
                    "file_line_range": [10, 22],
                    "severity": "HIGH",
                    "resource": "aws_s3_bucket.data",
                },
                {
                    "check_id": "CKV_K8S_8",
                    "check_name": "Liveness probe",
                    "file_path": "/k8s/deploy.yaml",
                    "file_line_range": [40, 40],
                    "severity": "LOW",
                    "resource": "Deployment.api",
                },
            ]
        }
    }
    findings = parse_checkov_results(raw, repo_root="/")
    assert len(findings) == 2
    assert findings[0]["check_id"] == "CKV_AWS_19"
    assert findings[0]["severity"] == "high"
    assert findings[0]["file"] == "tf/s3.tf"
    assert findings[0]["line"] == 10


def test_unknown_severity_defaults_to_medium():
    raw = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "X",
                    "check_name": "n",
                    "file_path": "/a.tf",
                    "file_line_range": [1, 1],
                    "resource": "r",
                },
            ]
        }
    }
    assert parse_checkov_results(raw, repo_root="/")[0]["severity"] == "medium"


def test_empty_results_returns_empty_list():
    assert (
        parse_checkov_results({"results": {"failed_checks": []}}, repo_root="/")
        == []
    )


def test_passed_checks_ignored():
    raw = {"results": {"failed_checks": [], "passed_checks": [{"check_id": "ok"}]}}
    assert parse_checkov_results(raw, repo_root="/") == []

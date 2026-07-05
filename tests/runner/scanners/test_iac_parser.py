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


def test_parse_attaches_code_window_from_source(tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n'
    )
    raw = {"results": {"failed_checks": [{
        "check_id": "CKV_AWS_20", "check_name": "S3 public", "file_path": "/main.tf",
        "file_line_range": [1, 4], "resource": "aws_s3_bucket.b", "severity": "HIGH",
    }]}}
    findings = parse_checkov_results(raw, repo_root=str(tmp_path))
    assert findings[0]["code_window"] is not None
    assert "aws_s3_bucket" in findings[0]["code_window"]
    assert findings[0]["code_window_start_line"] == 1


def test_parse_attaches_file_head_window_for_file_level_check(tmp_path):
    """File-level checks report line 0 — the window anchors at the file head."""
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nRUN apk add curl\nCMD [\"sh\"]\n")
    raw = {"results": {"failed_checks": [{
        "check_id": "CKV_DOCKER_3", "check_name": "No USER set", "file_path": "/Dockerfile",
        "file_line_range": [0, 0], "resource": "Dockerfile.", "severity": "MEDIUM",
    }]}}
    findings = parse_checkov_results(raw, repo_root=str(tmp_path))
    assert findings[0]["line"] == 0
    assert findings[0]["code_window"] is not None
    assert "FROM alpine" in findings[0]["code_window"]
    assert findings[0]["code_window_start_line"] == 1

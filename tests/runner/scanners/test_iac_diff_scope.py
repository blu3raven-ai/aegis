"""Checkov post-filter when diff-scoped."""
from __future__ import annotations

from runner.scanners.iac.scanner import IacScanConfig


def _job(**env):
    return {
        "jobType": "iac_scanning",
        "envVars": {
            "GIT_REPOS": "https://example.com/x.git",
            **env,
        },
    }


def test_config_reads_base_sha_and_scan_scope():
    cfg = IacScanConfig.from_job(_job(BASE_SHA="abc123", SCAN_SCOPE="diff_scoped"))
    assert cfg.base_sha == "abc123"
    assert cfg.scan_scope == "diff_scoped"


def test_config_defaults_when_env_unset():
    cfg = IacScanConfig.from_job(_job())
    assert cfg.base_sha is None
    assert cfg.scan_scope == "full_tree"

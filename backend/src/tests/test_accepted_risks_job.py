"""Unit test: _dispatch_scanner_jobs injects ACCEPTED_RISKS into the scanner env."""
from unittest.mock import patch

from src.scans import service as svc


def test_dispatch_injects_accepted_risks_env() -> None:
    captured: dict[str, dict[str, str]] = {}

    def _fake_create_job(*, job_type, org, run_id, env_vars):
        captured[job_type] = env_vars

    with patch("src.runner.jobs.create_job", _fake_create_job), \
         patch("src.settings.llm.service.build_llm_scan_env", return_value={}):
        svc._dispatch_scanner_jobs(
            scan_id="s1", repo_id="acme-org/example-repo", commit_sha="abc",
            scanners=["code_scanning"], org="acme-org",
            accepted_risks_json='[{"id": 1, "statement": "eval sandboxed", "path_glob": "app/*.py", "rule_id": null, "scanner": null}]',
        )

    env = captured["code_scanning"]
    assert '"statement": "eval sandboxed"' in env["ACCEPTED_RISKS"]


def test_dispatch_defaults_to_empty_list() -> None:
    captured: dict[str, dict[str, str]] = {}

    def _fake_create_job(*, job_type, org, run_id, env_vars):
        captured[job_type] = env_vars

    with patch("src.runner.jobs.create_job", _fake_create_job), \
         patch("src.settings.llm.service.build_llm_scan_env", return_value={}):
        svc._dispatch_scanner_jobs(
            scan_id="s1", repo_id="acme-org/example-repo", commit_sha="abc",
            scanners=["code_scanning"], org="acme-org",
        )

    assert captured["code_scanning"]["ACCEPTED_RISKS"] == "[]"

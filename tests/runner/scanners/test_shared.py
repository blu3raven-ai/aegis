"""Tests for ported lib.sh helpers."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from runner.scanners import _shared


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/acme/widget.git", "widget"),
    ("https://github.com/acme/widget", "widget"),
    ("https://github.com/acme/widget/", "widget"),
    ("https://github.com/acme/widget.git/", "widget"),
])
def test_repo_name_from_url(url, expected):
    assert _shared.repo_name_from_url(url) == expected


def test_parse_repos_comma_separated():
    assert _shared.parse_repos("https://x/a.git,https://x/b.git") == [
        "https://x/a.git", "https://x/b.git",
    ]


def test_parse_repos_newline_separated():
    assert _shared.parse_repos("https://x/a.git\nhttps://x/b.git") == [
        "https://x/a.git", "https://x/b.git",
    ]


def test_parse_repos_strips_empty():
    assert _shared.parse_repos("https://x/a.git,,\nhttps://x/b.git\n") == [
        "https://x/a.git", "https://x/b.git",
    ]


def test_parse_repos_from_file(tmp_path):
    p = tmp_path / "repos.txt"
    p.write_text("https://x/a.git\nhttps://x/b.git\n")
    assert _shared.parse_repos(str(p)) == ["https://x/a.git", "https://x/b.git"]


def test_parse_repos_skips_filesystem_check_for_long_input(monkeypatch):
    """Multi-MB or CSV/newline input should never touch the filesystem."""
    calls = {"count": 0}
    real_is_file = Path.is_file

    def tracking_is_file(self):
        calls["count"] += 1
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", tracking_is_file)

    long_csv = ",".join(f"https://x/{i}.git" for i in range(10))
    result = _shared.parse_repos(long_csv)
    assert len(result) == 10
    assert calls["count"] == 0

    multiline = "https://x/a.git\nhttps://x/b.git"
    _shared.parse_repos(multiline)
    assert calls["count"] == 0

    huge = "x" * 5000
    _shared.parse_repos(huge)
    assert calls["count"] == 0


@pytest.mark.parametrize("bad_url", [
    "git@github.com:acme/widget.git",
    "ssh://git@github.com/acme/widget.git",
    "file:///tmp/repo",
    "git://github.com/acme/widget.git",
    "http://github.com/acme/widget.git",
])
def test_clone_repo_rejects_non_https(bad_url, tmp_path):
    with pytest.raises(_shared.InsecureURLError):
        _shared.clone_repo(bad_url, tmp_path / "dest")


def test_clone_repo_injects_token(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _shared.clone_repo("https://github.com/acme/widget.git", tmp_path / "dest", token="abc123")

    assert "https://x-access-token:abc123@github.com/acme/widget.git" in captured["cmd"]


@pytest.mark.parametrize("bad_url", [
    "https://user@github.com/acme/widget.git",
    "https://user:pass@github.com/acme/widget.git",
])
def test_clone_repo_rejects_urls_with_userinfo(bad_url, tmp_path):
    with pytest.raises(_shared.InsecureURLError):
        _shared.clone_repo(bad_url, tmp_path / "dest", token="abc")


def test_clone_repo_scrubs_token_from_error_message(monkeypatch, tmp_path):
    """Token must not appear in the raised exception when clone fails."""
    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=128,
            cmd=cmd,
            stderr="fatal: could not read from https://x-access-token:SECRET_TOKEN@github.com/acme/widget.git\n",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(_shared.GitCloneError) as exc_info:
        _shared.clone_repo(
            "https://github.com/acme/widget.git",
            tmp_path / "dest",
            token="SECRET_TOKEN",
        )
    assert "SECRET_TOKEN" not in str(exc_info.value)
    assert "SECRET_TOKEN" not in repr(exc_info.value)


def test_clone_repo_no_token_no_injection(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _shared.clone_repo("https://github.com/acme/widget.git", tmp_path / "dest")

    assert not any("x-access-token" in part for part in captured["cmd"])


def test_log_scanning_emits_marker(capsys):
    _shared.log("scanning", "acme/widget")
    out = capsys.readouterr().out
    assert out == "[scanning] acme/widget\n"


def test_log_finished_emits_marker(capsys):
    _shared.log("done", "acme/widget")
    out = capsys.readouterr().out
    assert out == "[done] acme/widget\n"


def test_setup_output_dir_creates_path(tmp_path):
    result = _shared.setup_output_dir("job-123", base_dir=tmp_path)
    assert result == tmp_path / "job-123"
    assert result.exists()


def test_setup_output_dir_idempotent(tmp_path):
    _shared.setup_output_dir("job-123", base_dir=tmp_path)
    result = _shared.setup_output_dir("job-123", base_dir=tmp_path)
    assert result.exists()


def test_register_output_writes_manifest(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    f = out_dir / "x.json"
    f.write_text("{}")
    _shared.register_output(out_dir, f, "acme/widget")
    assert (out_dir / "_manifest.jsonl").exists()


# ---------------------------------------------------------------------------
# JobEnv
# ---------------------------------------------------------------------------

def test_job_env_reads_from_env_vars():
    from runner.scanners._shared import JobEnv
    env = JobEnv({"envVars": {"MY_KEY": "from_job"}})
    assert env.get("MY_KEY") == "from_job"


def test_job_env_falls_back_to_os_environ(monkeypatch):
    from runner.scanners._shared import JobEnv
    monkeypatch.setenv("MY_KEY", "from_os")
    env = JobEnv({"envVars": {}})
    assert env.get("MY_KEY") == "from_os"


def test_job_env_job_payload_takes_priority_over_os_environ(monkeypatch):
    from runner.scanners._shared import JobEnv
    monkeypatch.setenv("MY_KEY", "from_os")
    env = JobEnv({"envVars": {"MY_KEY": "from_job"}})
    assert env.get("MY_KEY") == "from_job"


def test_job_env_returns_default_when_missing():
    from runner.scanners._shared import JobEnv
    env = JobEnv({"envVars": {}})
    assert env.get("MISSING_KEY", "fallback") == "fallback"


def test_job_env_get_int_parses_valid():
    from runner.scanners._shared import JobEnv
    env = JobEnv({"envVars": {"COUNT": "8"}})
    assert env.get_int("COUNT", 4) == 8


def test_job_env_get_int_returns_default_for_invalid():
    from runner.scanners._shared import JobEnv
    env = JobEnv({"envVars": {"COUNT": "not_a_number"}})
    assert env.get_int("COUNT", 4) == 4


def test_job_env_get_int_returns_default_when_missing():
    from runner.scanners._shared import JobEnv
    env = JobEnv({"envVars": {}})
    assert env.get_int("COUNT", 4) == 4


def test_job_env_handles_missing_env_vars_key():
    from runner.scanners._shared import JobEnv
    env = JobEnv({})
    assert env.get("KEY", "default") == "default"


# ---------------------------------------------------------------------------
# BaseScanConfig
# ---------------------------------------------------------------------------

def test_base_scan_config_is_frozen():
    from runner.scanners._shared import BaseScanConfig
    cfg = BaseScanConfig(org_label="acme-org", run_id="job-1", concurrency=4)
    with pytest.raises(Exception):
        cfg.org_label = "other"  # type: ignore[misc]


def test_base_scan_config_stores_fields():
    from runner.scanners._shared import BaseScanConfig
    cfg = BaseScanConfig(org_label="acme-org", run_id="job-1", concurrency=4)
    assert cfg.org_label == "acme-org"
    assert cfg.run_id == "job-1"
    assert cfg.concurrency == 4


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

def test_scanner_config_error_is_scanner_error():
    from runner.scanners._shared import ScannerConfigError, ScannerError
    assert issubclass(ScannerConfigError, ScannerError)


def test_tool_error_is_scanner_error():
    from runner.scanners._shared import ScannerError, ToolError
    assert issubclass(ToolError, ScannerError)


def test_scanner_config_error_carries_message():
    from runner.scanners._shared import ScannerConfigError
    exc = ScannerConfigError("bad mode 'xyz'")
    assert "bad mode 'xyz'" in str(exc)


# ---------------------------------------------------------------------------
# Timeout constants
# ---------------------------------------------------------------------------

def test_timeout_constants_are_positive_floats():
    from runner.scanners import _shared
    constants = [
        _shared.TIMEOUT_CLONE,
        _shared.TIMEOUT_GIT_QUERY,
        _shared.TIMEOUT_SYFT_REPO,
        _shared.TIMEOUT_SYFT_IMAGE,
        _shared.TIMEOUT_CDXGEN,
        _shared.TIMEOUT_TRUFFLEHOG,
        _shared.TIMEOUT_OPENGREP,
    ]
    for c in constants:
        assert isinstance(c, float) and c > 0


def test_derive_html_url_strips_credentials_and_git_suffix():
    assert (
        _shared.derive_html_url("https://x-access-token:tok@github.com/acme/repo.git")
        == "https://github.com/acme/repo"
    )
    assert _shared.derive_html_url("https://github.com/acme/repo.git") == "https://github.com/acme/repo"
    assert _shared.derive_html_url("https://github.com/acme/repo") == "https://github.com/acme/repo"


def test_derive_html_url_preserves_self_hosted_host():
    # Host-agnostic: a self-hosted clone URL keeps its host (credentials stripped).
    assert (
        _shared.derive_html_url("https://gitlab.acme-corp.internal/acme/repo.git")
        == "https://gitlab.acme-corp.internal/acme/repo"
    )
    assert (
        _shared.derive_html_url("https://user:pw@ghe.acme-corp.internal/acme/repo.git")
        == "https://ghe.acme-corp.internal/acme/repo"
    )


# ── jobId / id path-traversal guard ──────────────────────────────────────────

@pytest.mark.parametrize("bad", ["../etc", "..", "a/b", "/abs", ".hidden", "", "x" * 129, "a b"])
def test_require_safe_id_rejects_traversal_and_junk(bad):
    with pytest.raises(ValueError):
        _shared.require_safe_id(bad, kind="jobId")


@pytest.mark.parametrize("ok", ["job-123", "abc_DEF.9", "0", "a" * 128])
def test_require_safe_id_accepts_plain_ids(ok):
    assert _shared.require_safe_id(ok) == ok


def test_setup_output_dir_rejects_unsafe_job_id(tmp_path):
    with pytest.raises(ValueError):
        _shared.setup_output_dir("../escape", base_dir=tmp_path)
    # a clean id still works and stays under base_dir
    out = _shared.setup_output_dir("job-1", base_dir=tmp_path)
    assert out == tmp_path / "job-1" and out.is_dir()

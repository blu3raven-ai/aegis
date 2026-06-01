"""Tests for aegis init command and init_templates module."""

from __future__ import annotations

import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli import init_templates
from aegis_cli.init_templates import (
    generate_policy,
    generate_project_config,
    patch_gitignore,
)


def _run(*args, input: str | None = None, env: dict | None = None):
    runner = CliRunner(mix_stderr=False)
    return runner.invoke(cli, list(args), input=input, catch_exceptions=False, env=env or {})


# ---------------------------------------------------------------------------
# init_templates: generate_project_config
# ---------------------------------------------------------------------------


def test_generate_project_config_valid_yaml(tmp_path):
    content = generate_project_config(
        backend_url="https://aegis.example.org",
        default_org="example-org",
        scanners=["dependencies", "sast"],
        severity_gate="critical",
    )
    parsed = yaml.safe_load(content)
    assert parsed["backend_url"] == "https://aegis.example.org"
    assert parsed["default_org"] == "example-org"
    assert parsed["scanners"] == ["dependencies", "sast"]
    assert parsed["severity_gate"] == "critical"
    assert parsed["policy_file"] == ".aegis/policy.yml"


def test_generate_project_config_no_token_field():
    """Token must never appear in .aegis.yml content."""
    content = generate_project_config(
        backend_url="https://aegis.example.org",
        default_org="example-org",
        scanners=["dependencies"],
        severity_gate="high",
    )
    assert "token" not in content.lower()
    assert "secret" not in content.lower()


def test_generate_project_config_contains_today():
    content = generate_project_config(
        backend_url="https://aegis.example.org",
        default_org="example-org",
        scanners=["sast"],
        severity_gate="none",
    )
    today = datetime.date.today().isoformat()
    assert today in content


def test_generate_project_config_custom_policy_file():
    content = generate_project_config(
        backend_url="https://aegis.example.org",
        default_org="example-org",
        scanners=["dependencies"],
        severity_gate="critical",
        policy_file="custom/policy.yml",
    )
    parsed = yaml.safe_load(content)
    assert parsed["policy_file"] == "custom/policy.yml"


# ---------------------------------------------------------------------------
# init_templates: generate_policy
# ---------------------------------------------------------------------------


def test_generate_policy_valid_yaml():
    content = generate_policy()
    parsed = yaml.safe_load(content)
    assert "block_on" in parsed
    assert "warn_on" in parsed
    assert "exclude_paths" in parsed


def test_generate_policy_has_critical_block():
    content = generate_policy()
    parsed = yaml.safe_load(content)
    block_severities = [
        entry["severity"] for entry in parsed["block_on"] if "severity" in entry
    ]
    assert "critical" in block_severities


# ---------------------------------------------------------------------------
# init_templates: patch_gitignore
# ---------------------------------------------------------------------------


def test_patch_gitignore_creates_file(tmp_path):
    gi = tmp_path / ".gitignore"
    assert not gi.exists()
    added = patch_gitignore(gi)
    assert added is True
    assert gi.exists()
    assert ".aegis/cache/" in gi.read_text()


def test_patch_gitignore_appends_to_existing(tmp_path):
    gi = tmp_path / ".gitignore"
    gi.write_text("node_modules/\n.env\n", encoding="utf-8")
    added = patch_gitignore(gi)
    assert added is True
    text = gi.read_text()
    assert "node_modules/" in text
    assert ".aegis/cache/" in text


def test_patch_gitignore_idempotent(tmp_path):
    gi = tmp_path / ".gitignore"
    # First call adds entries
    patch_gitignore(gi)
    content_after_first = gi.read_text()
    # Second call is a no-op
    added = patch_gitignore(gi)
    assert added is False
    assert gi.read_text() == content_after_first


def test_patch_gitignore_no_duplicate_entries(tmp_path):
    gi = tmp_path / ".gitignore"
    for _ in range(3):
        patch_gitignore(gi)
    text = gi.read_text()
    # .aegis/cache/ should appear exactly once
    assert text.count(".aegis/cache/") == 1


def test_patch_gitignore_appends_without_double_newline_when_file_ends_with_newline(tmp_path):
    gi = tmp_path / ".gitignore"
    gi.write_text("existing-entry/\n", encoding="utf-8")
    patch_gitignore(gi)
    text = gi.read_text()
    # Should not have more than two consecutive blank lines
    assert "\n\n\n" not in text


# ---------------------------------------------------------------------------
# init command: non-interactive (--yes flag)
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.init._validate_connection", return_value=(True, "200 OK"))
@patch("aegis_cli.commands.init.load_config")
def test_init_yes_creates_files(mock_cfg, mock_validate, tmp_path):
    from unittest.mock import MagicMock
    mock_cfg.return_value = MagicMock(
        base_url="https://aegis.example.org",
        api_token="tok-test",
        default_org="example-org",
    )
    result = _run(
        "init",
        "--project-dir", str(tmp_path),
        "--backend-url", "https://aegis.example.org",
        "--org", "example-org",
        "--scanners", "dependencies,sast",
        "--severity-gate", "critical",
        "--yes",
    )
    assert result.exit_code == 0, result.output + result.stderr
    assert (tmp_path / ".aegis.yml").exists()
    assert (tmp_path / ".aegis" / "policy.yml").exists()
    assert (tmp_path / ".gitignore").exists()


@patch("aegis_cli.commands.init._validate_connection", return_value=(True, "200 OK"))
@patch("aegis_cli.commands.init.load_config")
def test_init_yes_config_content(mock_cfg, mock_validate, tmp_path):
    from unittest.mock import MagicMock
    mock_cfg.return_value = MagicMock(
        base_url="https://aegis.example.org",
        api_token="",
        default_org="",
    )
    _run(
        "init",
        "--project-dir", str(tmp_path),
        "--backend-url", "https://custom.example.org",
        "--org", "example-org",
        "--scanners", "sast,secrets",
        "--severity-gate", "high",
        "--yes",
    )
    parsed = yaml.safe_load((tmp_path / ".aegis.yml").read_text())
    assert parsed["backend_url"] == "https://custom.example.org"
    assert parsed["default_org"] == "example-org"
    assert "sast" in parsed["scanners"]
    assert "secrets" in parsed["scanners"]
    assert parsed["severity_gate"] == "high"


@patch("aegis_cli.commands.init._validate_connection", return_value=(True, "200 OK"))
@patch("aegis_cli.commands.init.load_config")
def test_init_yes_no_token_in_aegis_yml(mock_cfg, mock_validate, tmp_path):
    """Token must never be written to .aegis.yml."""
    from unittest.mock import MagicMock
    mock_cfg.return_value = MagicMock(
        base_url="https://aegis.example.org",
        api_token="super-secret-token",
        default_org="example-org",
    )
    _run(
        "init",
        "--project-dir", str(tmp_path),
        "--backend-url", "https://aegis.example.org",
        "--api-token", "super-secret-token",
        "--org", "example-org",
        "--yes",
    )
    content = (tmp_path / ".aegis.yml").read_text()
    assert "super-secret-token" not in content


# ---------------------------------------------------------------------------
# init command: idempotent re-run (gitignore not duplicated)
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.init._validate_connection", return_value=(True, "200 OK"))
@patch("aegis_cli.commands.init.load_config")
def test_init_idempotent_gitignore(mock_cfg, mock_validate, tmp_path):
    from unittest.mock import MagicMock
    mock_cfg.return_value = MagicMock(
        base_url="https://aegis.example.org",
        api_token="tok",
        default_org="example-org",
    )
    common_args = [
        "init",
        "--project-dir", str(tmp_path),
        "--backend-url", "https://aegis.example.org",
        "--org", "example-org",
        "--yes",
        "--force",
    ]
    _run(*common_args)
    _run(*common_args)
    text = (tmp_path / ".gitignore").read_text()
    assert text.count(".aegis/cache/") == 1


# ---------------------------------------------------------------------------
# init command: existing .aegis.yml without --force → exit(1) when --yes
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.init._validate_connection", return_value=(True, "200 OK"))
@patch("aegis_cli.commands.init.load_config")
def test_init_yes_existing_config_no_force_fails(mock_cfg, mock_validate, tmp_path):
    from unittest.mock import MagicMock
    mock_cfg.return_value = MagicMock(
        base_url="https://aegis.example.org",
        api_token="tok",
        default_org="example-org",
    )
    (tmp_path / ".aegis.yml").write_text("backend_url: https://old.example.org\n")
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(
        cli,
        [
            "init",
            "--project-dir", str(tmp_path),
            "--backend-url", "https://aegis.example.org",
            "--org", "example-org",
            "--yes",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# init command: --force overwrites existing .aegis.yml
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.init._validate_connection", return_value=(True, "200 OK"))
@patch("aegis_cli.commands.init.load_config")
def test_init_force_overwrites_existing_config(mock_cfg, mock_validate, tmp_path):
    from unittest.mock import MagicMock
    mock_cfg.return_value = MagicMock(
        base_url="https://aegis.example.org",
        api_token="tok",
        default_org="example-org",
    )
    (tmp_path / ".aegis.yml").write_text("backend_url: https://old.example.org\n")
    result = _run(
        "init",
        "--project-dir", str(tmp_path),
        "--backend-url", "https://new.example.org",
        "--org", "example-org",
        "--yes",
        "--force",
    )
    assert result.exit_code == 0, result.output + result.stderr
    parsed = yaml.safe_load((tmp_path / ".aegis.yml").read_text())
    assert parsed["backend_url"] == "https://new.example.org"


# ---------------------------------------------------------------------------
# init command: connectivity warning (no failure) on bad backend
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.init._validate_connection", return_value=(False, "connection refused"))
@patch("aegis_cli.commands.init.load_config")
def test_init_connectivity_failure_warns_but_exits_zero(mock_cfg, mock_validate, tmp_path):
    from unittest.mock import MagicMock
    mock_cfg.return_value = MagicMock(
        base_url="https://unreachable.example.org",
        api_token="",
        default_org="example-org",
    )
    result = _run(
        "init",
        "--project-dir", str(tmp_path),
        "--backend-url", "https://unreachable.example.org",
        "--org", "example-org",
        "--yes",
    )
    # Files are written regardless
    assert (tmp_path / ".aegis.yml").exists()
    # stderr contains the connectivity warning
    assert "connection refused" in result.stderr or "Could not reach" in result.stderr


# ---------------------------------------------------------------------------
# init command: --skip-validation skips connectivity check
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.init.load_config")
def test_init_skip_validation(mock_cfg, tmp_path):
    from unittest.mock import MagicMock, patch as _patch
    mock_cfg.return_value = MagicMock(
        base_url="https://aegis.example.org",
        api_token="tok",
        default_org="example-org",
    )
    with _patch("aegis_cli.commands.init._validate_connection") as mock_val:
        result = _run(
            "init",
            "--project-dir", str(tmp_path),
            "--backend-url", "https://aegis.example.org",
            "--org", "example-org",
            "--yes",
            "--skip-validation",
        )
        mock_val.assert_not_called()
    assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# init command: --help
# ---------------------------------------------------------------------------


def test_init_help():
    result = _run("init", "--help")
    assert result.exit_code == 0
    assert "Initialize" in result.output or "init" in result.output

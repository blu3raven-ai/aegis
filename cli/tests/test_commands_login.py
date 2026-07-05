"""Tests for aegis login command."""

from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
import aegis_cli.commands.login as login_mod


def _run(*args, input: str | None = None):
    runner = CliRunner()
    return runner.invoke(cli, list(args), input=input, catch_exceptions=False)


# ---------------------------------------------------------------------------
# Writes config file with correct content
# ---------------------------------------------------------------------------


def test_login_writes_config_via_flags(tmp_path):
    config_path = tmp_path / "config.toml"
    with patch.object(login_mod, "CONFIG_PATH", config_path):
        result = _run(
            "login",
            "--base-url", "https://aegis.acme-org.example",
            "--api-token", "tok-abc123",
            "--default-org", "acme-org",
            "--force",
        )
    assert result.exit_code == 0, result.output
    assert config_path.exists()

    parsed = tomllib.loads(config_path.read_text())
    assert parsed["base_url"] == "https://aegis.acme-org.example"
    assert parsed["api_token"] == "tok-abc123"
    assert parsed["default_org"] == "acme-org"


def test_login_writes_config_via_prompts(tmp_path):
    config_path = tmp_path / "config.toml"
    # Provide prompt answers in order: base_url, api_token, default_org
    user_input = "\n".join([
        "https://aegis.acme-org.example",
        "tok-prompt",
        "acme-org",
    ])
    with patch.object(login_mod, "CONFIG_PATH", config_path):
        result = _run("login", input=user_input)
    assert result.exit_code == 0, result.output

    parsed = tomllib.loads(config_path.read_text())
    assert parsed["api_token"] == "tok-prompt"


# ---------------------------------------------------------------------------
# Restrictive file permissions (mode 0o600)
# ---------------------------------------------------------------------------


def test_login_sets_restrictive_file_perms(tmp_path):
    config_path = tmp_path / "config.toml"
    with patch.object(login_mod, "CONFIG_PATH", config_path):
        _run(
            "login",
            "--base-url", "https://aegis.acme-org.example",
            "--api-token", "tok-perm",
            "--default-org", "",
            "--force",
        )
    # On POSIX the file should be owner-read/write only
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(config_path).st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


# ---------------------------------------------------------------------------
# Overwrite behaviour: --force
# ---------------------------------------------------------------------------


def test_login_force_overwrites_existing_config(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text('base_url = "https://old.example.org"\napi_token = "old"\ndefault_org = ""\n')

    with patch.object(login_mod, "CONFIG_PATH", config_path):
        result = _run(
            "login",
            "--base-url", "https://new.example.org",
            "--api-token", "new-token",
            "--default-org", "",
            "--force",
        )
    assert result.exit_code == 0, result.output
    parsed = tomllib.loads(config_path.read_text())
    assert parsed["base_url"] == "https://new.example.org"
    assert parsed["api_token"] == "new-token"


# ---------------------------------------------------------------------------
# Existing config without --force: user confirms overwrite
# ---------------------------------------------------------------------------


def test_login_no_force_prompts_confirm_yes(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text('base_url = "https://old.example.org"\napi_token = "old"\ndefault_org = ""\n')

    # Confirm "y" then supply the three field prompts
    user_input = "\n".join([
        "y",                              # overwrite confirm
        "https://aegis.acme-org.example", # base_url
        "tok-new",                         # api_token
        "acme-org",                        # default_org
    ])
    with patch.object(login_mod, "CONFIG_PATH", config_path):
        result = _run("login", input=user_input)
    assert result.exit_code == 0, result.output
    parsed = tomllib.loads(config_path.read_text())
    assert parsed["api_token"] == "tok-new"


def test_login_no_force_prompts_confirm_no(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text('base_url = "https://old.example.org"\napi_token = "old"\ndefault_org = ""\n')

    with patch.object(login_mod, "CONFIG_PATH", config_path):
        result = _run("login", input="n\n")
    assert result.exit_code == 0, result.output
    assert "Aborted" in result.output
    # File unchanged
    parsed = tomllib.loads(config_path.read_text())
    assert parsed["api_token"] == "old"


# ---------------------------------------------------------------------------
# All four kwargs via flags — no prompts
# ---------------------------------------------------------------------------


def test_login_all_flags_no_prompts(tmp_path):
    config_path = tmp_path / "config.toml"
    with patch.object(login_mod, "CONFIG_PATH", config_path):
        result = _run(
            "login",
            "--base-url", "https://aegis.acme-org.example",
            "--api-token", "tok-flags",
            "--default-org", "acme-org",
            "--force",
        )
    assert result.exit_code == 0, result.output
    # "Saved to" confirmation
    assert "Saved to" in result.output
    assert config_path.exists()

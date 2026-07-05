"""Tests for config loading: env precedence over file over defaults."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

import pytest

from aegis_cli.config import load_config, _DEFAULT_BASE_URL


# ---------------------------------------------------------------------------
# Env var priority
# ---------------------------------------------------------------------------


def test_env_vars_take_priority(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_BASE_URL", "https://env.example.com")
    monkeypatch.setenv("AEGIS_API_TOKEN", "env-token-abc")
    monkeypatch.setenv("AEGIS_DEFAULT_ORG", "env-org")

    # Point config path to a non-existent file so file loading is skipped.
    monkeypatch.setattr("aegis_cli.config._CONFIG_PATH", tmp_path / "nofile.toml")
    monkeypatch.setattr("aegis_cli.config._CREDENTIALS_PATH", tmp_path / "nocreds")

    cfg = load_config()

    assert cfg.base_url == "https://env.example.com"
    assert cfg.api_token == "env-token-abc"
    assert cfg.default_org == "env-org"


def test_defaults_when_nothing_set(tmp_path, monkeypatch):
    for var in ("AEGIS_BASE_URL", "AEGIS_API_TOKEN", "AEGIS_DEFAULT_ORG"):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setattr("aegis_cli.config._CONFIG_PATH", tmp_path / "nofile.toml")
    monkeypatch.setattr("aegis_cli.config._CREDENTIALS_PATH", tmp_path / "nocreds")

    cfg = load_config()

    assert cfg.base_url == _DEFAULT_BASE_URL
    assert cfg.api_token == ""
    assert cfg.default_org is None


def test_trailing_slash_stripped_from_base_url(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_BASE_URL", "https://backend.example.com/")
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_DEFAULT_ORG", raising=False)
    monkeypatch.setattr("aegis_cli.config._CONFIG_PATH", tmp_path / "nofile.toml")
    monkeypatch.setattr("aegis_cli.config._CREDENTIALS_PATH", tmp_path / "nocreds")

    cfg = load_config()
    assert not cfg.base_url.endswith("/")


# ---------------------------------------------------------------------------
# File config
# ---------------------------------------------------------------------------


def test_file_config_loaded_when_env_absent(tmp_path, monkeypatch):
    for var in ("AEGIS_BASE_URL", "AEGIS_API_TOKEN", "AEGIS_DEFAULT_ORG"):
        monkeypatch.delenv(var, raising=False)

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_bytes(
        b'base_url = "https://file.example.com"\n'
        b'api_token = "file-token"\n'
        b'default_org = "file-org"\n'
    )
    monkeypatch.setattr("aegis_cli.config._CONFIG_PATH", cfg_path)
    monkeypatch.setattr("aegis_cli.config._CREDENTIALS_PATH", tmp_path / "nocreds")

    cfg = load_config()

    assert cfg.base_url == "https://file.example.com"
    assert cfg.api_token == "file-token"
    assert cfg.default_org == "file-org"


def test_env_overrides_file_config(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_API_TOKEN", "env-wins")

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_bytes(b'api_token = "file-loses"\n')
    monkeypatch.setattr("aegis_cli.config._CONFIG_PATH", cfg_path)
    monkeypatch.setattr("aegis_cli.config._CREDENTIALS_PATH", tmp_path / "nocreds")

    cfg = load_config()
    assert cfg.api_token == "env-wins"


def test_credentials_file_loaded(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_BASE_URL", raising=False)
    monkeypatch.delenv("AEGIS_DEFAULT_ORG", raising=False)

    creds_path = tmp_path / "credentials"
    creds_path.write_text("# comment line\nmy-secret-token\n")

    monkeypatch.setattr("aegis_cli.config._CONFIG_PATH", tmp_path / "nofile.toml")
    monkeypatch.setattr("aegis_cli.config._CREDENTIALS_PATH", creds_path)

    cfg = load_config()
    assert cfg.api_token == "my-secret-token"


def test_credentials_file_skips_blank_and_comments(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_BASE_URL", raising=False)
    monkeypatch.delenv("AEGIS_DEFAULT_ORG", raising=False)

    creds_path = tmp_path / "credentials"
    creds_path.write_text("# this is a comment\n\nreal-token\n")

    monkeypatch.setattr("aegis_cli.config._CONFIG_PATH", tmp_path / "nofile.toml")
    monkeypatch.setattr("aegis_cli.config._CREDENTIALS_PATH", creds_path)

    cfg = load_config()
    assert cfg.api_token == "real-token"

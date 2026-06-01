"""Tests for aegis scan command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.client import AegisAPIError


def _make_cfg(org="example-org", token="tok"):
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _run_cli(*args, env=None):
    runner = CliRunner()
    return runner.invoke(cli, list(args), catch_exceptions=False, env=env or {})


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.scan.AegisClient")
@patch("aegis_cli.commands.scan.load_config")
def test_scan_triggers_and_prints_queued(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    client_inst.trigger_scan.return_value = {
        "runs": [{"org": "example-org", "queued": True}],
        "message": "Started 1 dependency scan(s)",
    }
    mock_client_cls.return_value = client_inst

    result = _run_cli("scan", "--org", "example-org")

    assert result.exit_code == 0
    assert "queued" in result.output.lower() or "scan" in result.output.lower()
    client_inst.trigger_scan.assert_called_once_with(
        org="example-org", scanner_type="dependencies", repo=None
    )


@patch("aegis_cli.commands.scan.AegisClient")
@patch("aegis_cli.commands.scan.load_config")
def test_scan_explicit_scanner(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    client_inst.trigger_scan.return_value = {"runs": [], "message": "ok"}
    mock_client_cls.return_value = client_inst

    _run_cli("scan", "--scanner", "secrets", "--org", "example-org")

    client_inst.trigger_scan.assert_called_once_with(
        org="example-org", scanner_type="secrets", repo=None
    )


# ---------------------------------------------------------------------------
# Missing config
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.scan.load_config")
def test_scan_exits_1_when_no_org(mock_cfg):
    cfg = _make_cfg(org=None, token="tok")
    mock_cfg.return_value = cfg
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "org" in result.output.lower() or "error" in result.output.lower()


@patch("aegis_cli.commands.scan.load_config")
def test_scan_exits_1_when_no_token(mock_cfg):
    cfg = _make_cfg(token="")
    mock_cfg.return_value = cfg
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"], catch_exceptions=False)
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# API error
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.scan.AegisClient")
@patch("aegis_cli.commands.scan.load_config")
def test_scan_exits_1_on_api_error(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    client_inst.trigger_scan.side_effect = AegisAPIError("conflict", status_code=409)
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--org", "example-org"], catch_exceptions=False)
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.scan.AegisClient")
@patch("aegis_cli.commands.scan.load_config")
def test_scan_json_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    payload = {"runs": [{"org": "example-org", "queued": True}], "message": "ok"}
    client_inst.trigger_scan.return_value = payload
    mock_client_cls.return_value = client_inst

    result = _run_cli("scan", "--org", "example-org", "--json")

    assert result.exit_code == 0
    import json
    parsed = json.loads(result.output)
    assert "runs" in parsed

"""Tests for aegis status command."""

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


def _make_client(scan_status_return=None, side_effect=None):
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    if side_effect:
        client_inst.get_scan_status.side_effect = side_effect
    else:
        client_inst.get_scan_status.return_value = scan_status_return or {}
    return client_inst


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.status.AegisClient")
@patch("aegis_cli.commands.status.load_config")
def test_status_prints_run_details(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    run = {
        "id": "run-abc",
        "org": "example-org",
        "status": "completed",
        "findingsCount": 3,
        "progress": {"percent": 100, "stage": "completed"},
    }
    mock_client_cls.return_value = _make_client(scan_status_return=run)

    runner = CliRunner()
    result = runner.invoke(cli, ["status", "run-abc", "--org", "example-org"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "run-abc" in result.output


@patch("aegis_cli.commands.status.AegisClient")
@patch("aegis_cli.commands.status.load_config")
def test_status_json_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    run = {"id": "run-abc", "org": "example-org", "status": "running", "findingsCount": 0}
    mock_client_cls.return_value = _make_client(scan_status_return=run)

    runner = CliRunner()
    result = runner.invoke(
        cli, ["status", "run-abc", "--org", "example-org", "--json"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    import json
    parsed = json.loads(result.output)
    assert parsed["id"] == "run-abc"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.status.load_config")
def test_status_exits_1_when_no_org(mock_cfg):
    mock_cfg.return_value = _make_cfg(org=None)
    runner = CliRunner()
    result = runner.invoke(cli, ["status", "run-abc"], catch_exceptions=False)
    assert result.exit_code == 1


@patch("aegis_cli.commands.status.AegisClient")
@patch("aegis_cli.commands.status.load_config")
def test_status_exits_1_on_not_found(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        side_effect=AegisAPIError("not found", status_code=404)
    )
    runner = CliRunner()
    result = runner.invoke(
        cli, ["status", "unknown-run", "--org", "example-org"],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    assert "not found" in result.output.lower()

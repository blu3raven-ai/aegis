"""CLI tests for `aegis epss` subcommands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.client import AegisAPIError
from aegis_cli.main import cli


def _make_cfg(org: str = "example-org", token: str = "testtoken") -> MagicMock:
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _make_score(**kwargs) -> dict:
    return {
        "cve": kwargs.get("cve", "CVE-2021-44228"),
        "score": kwargs.get("score", 0.97412),
        "percentile": kwargs.get("percentile", 0.99987),
        "scored_date": kwargs.get("scored_date", "2024-05-13"),
        "fetched_at": kwargs.get("fetched_at", "2024-05-13T12:00:00+00:00"),
    }


def _make_top(**kwargs) -> dict:
    return {
        "count": kwargs.get("count", 2),
        "findings": kwargs.get("findings", [
            {
                "finding_id": 101,
                "tool": "deps",
                "repo": "example/app",
                "severity": "high",
                "identity_key": "k1",
                "cve": "CVE-2021-44228",
                "epss_score": 0.97412,
                "epss_percentile": 0.99987,
                "scored_date": "2024-05-13",
            },
            {
                "finding_id": 102,
                "tool": "container",
                "repo": "example/app",
                "severity": "medium",
                "identity_key": "k2",
                "cve": "CVE-2024-11111",
                "epss_score": 0.10,
                "epss_percentile": 0.50,
                "scored_date": "2024-05-13",
            },
        ]),
    }


# ---------------------------------------------------------------------------
# epss --help
# ---------------------------------------------------------------------------


def test_epss_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "--help"])
    assert result.exit_code == 0
    assert "score" in result.output
    assert "top" in result.output
    assert "refresh" in result.output


# ---------------------------------------------------------------------------
# epss score
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_score_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_epss_score.return_value = _make_score()
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "score", "CVE-2021-44228"])

    assert result.exit_code == 0
    assert "CVE-2021-44228" in result.output
    assert "0.97412" in result.output
    assert "97.41%" in result.output
    assert "2024-05-13" in result.output


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_score_not_found(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_epss_score.side_effect = AegisAPIError("not in the EPSS feed", 404)
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "score", "CVE-9999-00000"])

    assert result.exit_code != 0
    assert "not in the EPSS feed" in result.output


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_score_api_error(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_epss_score.side_effect = AegisAPIError("Internal Server Error", 500)
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "score", "CVE-2021-44228"])
    assert result.exit_code != 0
    assert "Internal Server Error" in result.output


# ---------------------------------------------------------------------------
# epss top
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_top_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_epss_top.return_value = _make_top()
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "top", "--org", "example-org", "--limit", "5"])

    assert result.exit_code == 0
    assert "CVE-2021-44228" in result.output
    assert "CVE-2024-11111" in result.output
    inst.get_epss_top.assert_called_once_with(org_id="example-org", limit=5)


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_top_no_org_raises(mock_cfg, mock_client_cls):
    cfg = _make_cfg()
    cfg.default_org = ""
    mock_cfg.return_value = cfg

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "top"])
    assert result.exit_code != 0


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_top_empty(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_epss_top.return_value = {"count": 0, "findings": []}
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "top", "--org", "example-org"])
    assert result.exit_code == 0
    assert "No open findings" in result.output


# ---------------------------------------------------------------------------
# epss refresh
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_refresh_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.trigger_epss_refresh.return_value = {"fetched": 250000, "new": 1500}
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "refresh"])

    assert result.exit_code == 0
    assert "250,000" in result.output
    assert "1,500" in result.output


@patch("aegis_cli.commands.epss.AegisClient")
@patch("aegis_cli.commands.epss.load_config")
def test_refresh_api_error(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.trigger_epss_refresh.side_effect = AegisAPIError("upstream timeout", 502)
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["epss", "refresh"])
    assert result.exit_code != 0
    assert "upstream timeout" in result.output

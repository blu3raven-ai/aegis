"""CLI tests for `aegis kev` subcommands."""
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


def _make_kev_entry(**kwargs) -> dict:
    return {
        "cve_id": kwargs.get("cve_id", "CVE-2021-44228"),
        "vendor_project": kwargs.get("vendor_project", "Apache"),
        "product": kwargs.get("product", "Log4j2"),
        "vulnerability_name": kwargs.get("vulnerability_name", "Apache Log4j2 RCE"),
        "date_added": kwargs.get("date_added", "2021-12-10"),
        "short_description": kwargs.get("short_description", "JNDI RCE via LDAP."),
        "required_action": kwargs.get("required_action", "Apply updates per vendor."),
        "due_date": kwargs.get("due_date", "2021-12-24"),
        "known_ransomware_use": kwargs.get("known_ransomware_use", True),
        "notes": kwargs.get("notes", ""),
        "cwes": kwargs.get("cwes", ["CWE-20"]),
        "ingested_at": kwargs.get("ingested_at", "2024-01-01T00:00:00+00:00"),
    }


def _make_exposure_summary(**kwargs) -> dict:
    return {
        "open_findings_total": kwargs.get("open_findings_total", 1450),
        "open_findings_in_kev": kwargs.get("open_findings_in_kev", 23),
        "kev_overdue": kwargs.get("kev_overdue", 8),
        "kev_with_ransomware": kwargs.get("kev_with_ransomware", 5),
        "top_kev_findings": kwargs.get("top_kev_findings", [
            {
                "cve_id": "CVE-2021-44228",
                "vulnerability_name": "Apache Log4j2 RCE",
                "finding_count": 12,
                "due_date": "2021-12-24",
                "known_ransomware_use": True,
            },
            {
                "cve_id": "CVE-2024-21762",
                "vulnerability_name": "Fortinet FortiOS OOB Write",
                "finding_count": 6,
                "due_date": "2024-02-16",
                "known_ransomware_use": False,
            },
        ]),
    }


# ---------------------------------------------------------------------------
# kev --help
# ---------------------------------------------------------------------------

def test_kev_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "--help"])
    assert result.exit_code == 0
    assert "exposure" in result.output
    assert "show" in result.output
    assert "recent" in result.output


# ---------------------------------------------------------------------------
# kev exposure
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_exposure_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_kev_exposure_summary.return_value = _make_exposure_summary()
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "exposure", "--org", "example-org"])

    assert result.exit_code == 0
    assert "CISA KEV Exposure Summary" in result.output
    assert "1,450" in result.output
    assert "23" in result.output
    assert "8" in result.output
    assert "CVE-2021-44228" in result.output
    assert "aegis kev show" in result.output


@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_exposure_no_org_raises(mock_cfg, mock_client_cls):
    cfg = _make_cfg()
    cfg.default_org = ""
    mock_cfg.return_value = cfg

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "exposure"])
    assert result.exit_code != 0


@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_exposure_api_error(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_kev_exposure_summary.side_effect = AegisAPIError("Internal Server Error", 500)
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "exposure", "--org", "example-org"])
    assert result.exit_code != 0
    assert "Internal Server Error" in result.output


@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_exposure_zero_findings(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_kev_exposure_summary.return_value = _make_exposure_summary(
        open_findings_total=0,
        open_findings_in_kev=0,
        kev_overdue=0,
        kev_with_ransomware=0,
        top_kev_findings=[],
    )
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "exposure", "--org", "example-org"])
    assert result.exit_code == 0
    assert "0" in result.output


# ---------------------------------------------------------------------------
# kev show
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_show_entry(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_kev_entry.return_value = _make_kev_entry()
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "show", "CVE-2021-44228"])

    assert result.exit_code == 0
    assert "CVE-2021-44228" in result.output
    assert "Apache" in result.output
    assert "Log4j2" in result.output
    assert "Yes" in result.output  # known_ransomware_use


@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_show_not_found(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_kev_entry.side_effect = AegisAPIError("not in the CISA KEV catalog", 404)
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "show", "CVE-9999-00000"])

    assert result.exit_code != 0
    assert "not in the CISA KEV catalog" in result.output


# ---------------------------------------------------------------------------
# kev recent
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_recent_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_kev_recent.return_value = {
        "count": 2,
        "entries": [
            _make_kev_entry(cve_id="CVE-2024-11111", date_added="2024-06-01", known_ransomware_use=False),
            _make_kev_entry(cve_id="CVE-2024-22222", date_added="2024-06-05", known_ransomware_use=True),
        ],
    }
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "recent", "--days", "30"])

    assert result.exit_code == 0
    assert "CVE-2024-11111" in result.output
    assert "CVE-2024-22222" in result.output
    assert "RANSOMWARE" in result.output


@patch("aegis_cli.commands.kev.AegisClient")
@patch("aegis_cli.commands.kev.load_config")
def test_recent_empty(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    inst = MagicMock()
    inst.get_kev_recent.return_value = {"count": 0, "entries": []}
    mock_client_cls.return_value = inst

    runner = CliRunner()
    result = runner.invoke(cli, ["kev", "recent"])

    assert result.exit_code == 0
    assert "No new entries" in result.output

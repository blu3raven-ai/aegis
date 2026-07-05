"""Tests for aegis findings command — calls the aggregated /api/v1/findings."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.client import AegisAPIError


def _make_cfg(org="example-org", token="tok"):
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _make_client(response=None, side_effect=None):
    """Build a mock AegisClient whose list_findings returns the envelope."""
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    if side_effect:
        client_inst.list_findings.side_effect = side_effect
    else:
        client_inst.list_findings.return_value = response if response is not None else {
            "findings": [],
            "next_cursor": None,
            "total_count": 0,
        }
    return client_inst


# Flat-shape findings as returned by GET /api/v1/findings.
_SAMPLE_FINDINGS = [
    {
        "id": "fnd-1",
        "scanner": "deps",
        "severity": "critical",
        "state": "open",
        "title": "lodash",
        "cve": "CVE-2023-0001",
        "package": "lodash@4.17.15",
        "file_path": None,
        "line": None,
        "repo": "example-org/api-service",
        "org_id": "example-org",
        "created_at": "2026-01-01T00:00:00",
        "updated_at": "2026-01-01T00:00:00",
    },
    {
        "id": "fnd-2",
        "scanner": "deps",
        "severity": "high",
        "state": "open",
        "title": "express",
        "cve": None,
        "package": "express@4.18.0",
        "file_path": None,
        "line": None,
        "repo": "example-org/api-service",
        "org_id": "example-org",
        "created_at": "2026-01-02T00:00:00",
        "updated_at": "2026-01-02T00:00:00",
    },
]


def _envelope(findings, next_cursor=None, total=None):
    return {
        "findings": findings,
        "next_cursor": next_cursor,
        "total_count": total if total is not None else len(findings),
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_prints_table(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(response=_envelope(_SAMPLE_FINDINGS))

    runner = CliRunner()
    result = runner.invoke(cli, ["findings", "--org", "example-org"], catch_exceptions=False)

    assert result.exit_code == 0
    assert (
        "critical" in result.output.lower()
        or "lodash" in result.output.lower()
        or "2 finding" in result.output.lower()
    )


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_json_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(response=_envelope(_SAMPLE_FINDINGS))

    runner = CliRunner()
    result = runner.invoke(
        cli, ["findings", "--org", "example-org", "--json"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert len(parsed) == 2


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_empty(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(response=_envelope([]))

    runner = CliRunner()
    result = runner.invoke(cli, ["findings", "--org", "example-org"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "0" in result.output or "no findings" in result.output.lower()


# ---------------------------------------------------------------------------
# Filter pass-through to the aggregated endpoint
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_passes_severity_filter(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client(response=_envelope([]))
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    runner.invoke(
        cli,
        ["findings", "--org", "example-org", "--severity", "critical,high"],
        catch_exceptions=False,
    )

    call_kwargs = client_inst.list_findings.call_args.kwargs
    assert "critical" in (call_kwargs.get("severity") or [])
    assert "high" in (call_kwargs.get("severity") or [])


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_passes_scanner_filter(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client(response=_envelope([]))
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    runner.invoke(
        cli,
        ["findings", "--org", "example-org", "--scanner", "secrets"],
        catch_exceptions=False,
    )

    call_kwargs = client_inst.list_findings.call_args.kwargs
    assert "secrets" in (call_kwargs.get("scanner") or [])


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_passes_state_filter(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client(response=_envelope([]))
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    runner.invoke(
        cli,
        ["findings", "--org", "example-org", "--state", "open,dismissed"],
        catch_exceptions=False,
    )

    call_kwargs = client_inst.list_findings.call_args.kwargs
    assert call_kwargs.get("state") == ["open", "dismissed"]


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_passes_q_and_cve(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client(response=_envelope([]))
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    runner.invoke(
        cli,
        ["findings", "--org", "example-org", "--q", "log4j", "--cve", "CVE-2021-44228"],
        catch_exceptions=False,
    )

    call_kwargs = client_inst.list_findings.call_args.kwargs
    assert call_kwargs.get("q") == "log4j"
    assert call_kwargs.get("cve") == "CVE-2021-44228"


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_passes_sort_direction_limit(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client(response=_envelope([]))
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    runner.invoke(
        cli,
        [
            "findings", "--org", "example-org",
            "--sort", "created_at",
            "--direction", "asc",
            "--limit", "10",
        ],
        catch_exceptions=False,
    )

    call_kwargs = client_inst.list_findings.call_args.kwargs
    assert call_kwargs.get("sort") == "created_at"
    assert call_kwargs.get("direction") == "asc"
    assert call_kwargs.get("limit") == 10


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_passes_cursor(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client(response=_envelope([]))
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    runner.invoke(
        cli,
        ["findings", "--org", "example-org", "--cursor", "OPAQUE_CURSOR"],
        catch_exceptions=False,
    )

    call_kwargs = client_inst.list_findings.call_args.kwargs
    assert call_kwargs.get("cursor") == "OPAQUE_CURSOR"


# ---------------------------------------------------------------------------
# Client-side --repo filter (endpoint has no repo-only filter)
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_repo_filter_is_client_side(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    findings = [
        {**_SAMPLE_FINDINGS[0], "repo": "example-org/api-service"},
        {**_SAMPLE_FINDINGS[1], "repo": "example-org/other"},
    ]
    client_inst = _make_client(response=_envelope(findings))
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["findings", "--org", "example-org", "--repo", "api-service", "--json"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert len(parsed) == 1
    assert parsed[0]["repo"] == "example-org/api-service"
    # repo is NOT forwarded to the endpoint — it has no repo filter.
    call_kwargs = client_inst.list_findings.call_args.kwargs
    assert "repo" not in call_kwargs


# ---------------------------------------------------------------------------
# Pagination surfacing
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_table_shows_next_cursor(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        response=_envelope(_SAMPLE_FINDINGS, next_cursor="NEXT_PAGE", total=500)
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["findings", "--org", "example-org"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "NEXT_PAGE" in result.output
    assert "500" in result.output


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.findings.load_config")
def test_findings_exits_1_when_no_org(mock_cfg):
    mock_cfg.return_value = _make_cfg(org=None)
    runner = CliRunner()
    result = runner.invoke(cli, ["findings"], catch_exceptions=False)
    assert result.exit_code == 1


@patch("aegis_cli.commands.findings.AegisClient")
@patch("aegis_cli.commands.findings.load_config")
def test_findings_exits_1_on_api_error(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        side_effect=AegisAPIError("server error", status_code=500)
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["findings", "--org", "example-org"], catch_exceptions=False)
    assert result.exit_code == 1

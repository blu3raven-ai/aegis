"""CLI tests for `aegis watch`."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.sse_client import SseMessage


def _make_cfg(token: str = "tok") -> MagicMock:
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = "example-org"
    return cfg


def _finding_msg(
    *,
    event_type: str = "finding.created",
    severity: str = "high",
    scanner: str = "secrets",
    finding_id: str = "f-1",
    org: str | None = None,
) -> SseMessage:
    payload = {
        "finding_id": finding_id,
        "severity": severity,
        "scanner_type": scanner,
    }
    if org is not None:
        payload["org_id"] = org
    return SseMessage(
        event_type=event_type,
        data={"event_id": "evt-1", "payload": payload},
        event_id="1",
    )


# ---------------------------------------------------------------------------
# Happy path: prints finding events
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_prints_finding_events(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    mock_stream.return_value = iter([
        _finding_msg(severity="critical", scanner="sast", finding_id="f-9"),
    ])

    runner = CliRunner()
    result = runner.invoke(cli, ["watch"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "CRITICAL" in result.output
    assert "sast" in result.output
    assert "f-9" in result.output


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_filters_out_non_finding_events(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    mock_stream.return_value = iter([
        SseMessage(event_type="scan.completed", data={"payload": {}}),
        _finding_msg(finding_id="f-keep"),
    ])

    runner = CliRunner()
    result = runner.invoke(cli, ["watch"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "f-keep" in result.output
    assert "scan.completed" not in result.output


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_json_emits_parseable_lines(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    mock_stream.return_value = iter([
        _finding_msg(severity="high", scanner="secrets", finding_id="f-1"),
        _finding_msg(severity="low", scanner="sast", finding_id="f-2"),
    ])

    runner = CliRunner()
    result = runner.invoke(cli, ["watch", "--json"], catch_exceptions=False)

    assert result.exit_code == 0
    lines = [ln for ln in result.output.strip().splitlines() if ln.strip()]
    assert len(lines) == 2
    parsed = [json.loads(ln) for ln in lines]
    assert parsed[0]["finding_id"] == "f-1"
    assert parsed[1]["finding_id"] == "f-2"


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_severity_filter(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    mock_stream.return_value = iter([
        _finding_msg(severity="low", finding_id="skip-me"),
        _finding_msg(severity="critical", finding_id="keep-me"),
    ])

    runner = CliRunner()
    result = runner.invoke(
        cli, ["watch", "--severity", "critical,high"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert "keep-me" in result.output
    assert "skip-me" not in result.output


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_scanner_filter(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    mock_stream.return_value = iter([
        _finding_msg(scanner="dependencies", finding_id="skip-me"),
        _finding_msg(scanner="secrets", finding_id="keep-me"),
    ])

    runner = CliRunner()
    result = runner.invoke(
        cli, ["watch", "--scanner", "secrets,sast"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert "keep-me" in result.output
    assert "skip-me" not in result.output


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_org_filter(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    mock_stream.return_value = iter([
        _finding_msg(org="other-org", finding_id="skip-me"),
        _finding_msg(org="example-org", finding_id="keep-me"),
    ])

    runner = CliRunner()
    result = runner.invoke(
        cli, ["watch", "--org", "example-org"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert "keep-me" in result.output
    assert "skip-me" not in result.output


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.watch.load_config")
def test_watch_exits_1_when_no_token(mock_cfg) -> None:
    mock_cfg.return_value = _make_cfg(token="")
    runner = CliRunner()
    result = runner.invoke(cli, ["watch"], catch_exceptions=False)
    assert result.exit_code == 1


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_handles_http_status_error(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    resp = httpx.Response(401, request=httpx.Request("GET", "https://x/y"))
    mock_stream.side_effect = httpx.HTTPStatusError("unauth", request=resp.request, response=resp)

    runner = CliRunner()
    result = runner.invoke(cli, ["watch"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "401" in result.output or "401" in (result.stderr or "")


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_handles_connection_error(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()
    mock_stream.side_effect = httpx.ConnectError("refused")

    runner = CliRunner()
    result = runner.invoke(cli, ["watch"], catch_exceptions=False)
    assert result.exit_code == 1


@patch("aegis_cli.commands.watch.stream_events")
@patch("aegis_cli.commands.watch.load_config")
def test_watch_exits_cleanly_on_keyboard_interrupt(mock_cfg, mock_stream) -> None:
    mock_cfg.return_value = _make_cfg()

    def _raise_interrupt(*_a, **_kw):
        yield _finding_msg(finding_id="f-1")
        raise KeyboardInterrupt()

    mock_stream.side_effect = _raise_interrupt

    runner = CliRunner()
    result = runner.invoke(cli, ["watch"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "f-1" in result.output

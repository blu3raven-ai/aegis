"""Smoke tests for the runner-agent CLI entrypoint.

The CLI is a thin click wrapper over RunnerAgent; these exercise its wiring and
branch logic (arg validation, HTTPS guard, register happy path, missing config)
without touching the network or the real config file."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner.vuln_runner import cli


def test_help_lists_commands():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "configure" in result.output and "start" in result.output


def test_configure_rejects_non_https_without_insecure():
    result = CliRunner().invoke(cli, ["configure", "--url", "http://portal.local", "--token", "t"])
    assert result.exit_code == 1
    assert "HTTPS" in result.output


def test_configure_missing_required_args_errors():
    result = CliRunner().invoke(cli, ["configure"])
    assert result.exit_code == 2  # click usage error for missing --url/--token


def test_configure_registers_and_saves_on_success():
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"runnerId": "r-1", "authToken": "tok", "status": "pending"}
    client = MagicMock()
    client.__enter__.return_value.post.return_value = resp

    with patch("runner.vuln_runner.httpx.Client", return_value=client), \
         patch("runner.vuln_runner.save_config") as save:
        result = CliRunner().invoke(
            cli, ["configure", "--url", "https://portal.local", "--token", "t", "--name", "box"]
        )
    assert result.exit_code == 0
    assert "r-1" in result.output
    saved = save.call_args[0][0]
    assert saved["runnerId"] == "r-1" and saved["portalUrl"] == "https://portal.local"


def test_start_errors_when_no_config():
    with patch("runner.vuln_runner.load_config", side_effect=FileNotFoundError("no config; run configure")):
        result = CliRunner().invoke(cli, ["start"])
    assert result.exit_code == 1
    assert "configure" in result.output

"""CLI invocation tests for aegis triage subcommands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.client import AegisAPIError
from aegis_cli.main import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(org: str = "example-org", token: str = "testtoken") -> MagicMock:
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _make_client(findings=None) -> MagicMock:
    """Build a mock AegisClient with iter_all_findings returning *findings*."""
    inst = MagicMock()
    inst.iter_all_findings.return_value = findings if findings is not None else []
    inst.dismiss_finding.return_value = {"status": "dismissed"}
    inst.snooze_finding.return_value = {"status": "snoozed"}
    inst.assign_finding.return_value = {"status": "assigned"}
    inst.mark_finding_fixed.return_value = {"status": "fixed"}
    return inst


_SAMPLE_FINDINGS = [
    {
        "id": "F-1",
        "title": "SQL injection in login handler",
        "severity": "critical",
        "state": "open",
        "repo": "example-org/api",
        "created_at": "2025-01-01T00:00:00+00:00",
    },
    {
        "id": "F-2",
        "title": "Exposed secret in env file",
        "severity": "high",
        "state": "open",
        "repo": "example-org/api",
        "created_at": "2025-02-01T00:00:00+00:00",
    },
]


# ---------------------------------------------------------------------------
# triage --help
# ---------------------------------------------------------------------------

def test_triage_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["triage", "--help"])
    assert result.exit_code == 0
    assert "dismiss" in result.output
    assert "snooze" in result.output
    assert "assign" in result.output
    assert "mark-fixed" in result.output
    assert "interactive" in result.output


# ---------------------------------------------------------------------------
# dismiss
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_dismiss_by_finding_ids(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client()
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "dismiss", "--finding-ids", "F-1,F-2", "--reason", "accepted risk", "--yes"],
    )
    assert result.exit_code == 0
    assert "Dismissed 2/2" in result.output
    assert client.dismiss_finding.call_count == 2


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_dismiss_by_filter(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client(findings=_SAMPLE_FINDINGS)
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "dismiss", "--severity", "critical,high",
         "--reason", "patching freeze", "--yes"],
    )
    assert result.exit_code == 0
    assert "Dismissed 2/2" in result.output


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_dismiss_no_matches(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=[])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "dismiss", "--severity", "critical", "--reason", "ok", "--yes"],
    )
    assert result.exit_code == 0
    assert "No findings matched" in result.output


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_dismiss_confirmation_abort(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

    runner = CliRunner()
    # Simulate user typing 'n' at the confirmation prompt
    result = runner.invoke(
        cli,
        ["triage", "dismiss", "--severity", "critical", "--reason", "ok"],
        input="n\n",
    )
    assert result.exit_code == 0
    assert "Aborted" in result.output


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_dismiss_partial_failure(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client()
    # Second call raises an error
    client.dismiss_finding.side_effect = [None, AegisAPIError("server error")]
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "dismiss", "--finding-ids", "F-1,F-2", "--reason", "ok", "--yes"],
    )
    assert result.exit_code == 0
    assert "Dismissed 1/2" in result.output


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_dismiss_requires_reason(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client()

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "dismiss", "--finding-ids", "F-1", "--yes"],
    )
    assert result.exit_code != 0
    assert "reason" in result.output.lower() or "missing" in result.output.lower()


# ---------------------------------------------------------------------------
# snooze
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_snooze_by_finding_ids(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client()
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "snooze", "--finding-ids", "F-1",
         "--until", "30d", "--reason", "patching freeze", "--yes"],
    )
    assert result.exit_code == 0
    assert "Snoozed 1/1" in result.output
    client.snooze_finding.assert_called_once_with("F-1", until_days=30, reason="patching freeze")


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_snooze_by_scanner(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client(findings=_SAMPLE_FINDINGS)
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "snooze", "--scanner", "deps",
         "--until", "1w", "--reason", "freeze", "--yes"],
    )
    assert result.exit_code == 0
    assert "Snoozed" in result.output
    assert "7 day" in result.output


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_snooze_invalid_duration(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client()

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "snooze", "--finding-ids", "F-1",
         "--until", "invalid", "--reason", "test", "--yes"],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# assign
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_assign_by_severity(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    # Return only the critical finding to simulate server-side filtering
    client = _make_client(findings=[_SAMPLE_FINDINGS[0]])
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "assign", "--severity", "critical",
         "--to", "dev@example.org", "--yes"],
    )
    assert result.exit_code == 0
    assert "Assigned 1/1" in result.output
    client.assign_finding.assert_called_once_with("F-1", assignee="dev@example.org")


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_assign_requires_to(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client()

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "assign", "--finding-ids", "F-1", "--yes"],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# mark-fixed
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_mark_fixed_multiple_ids(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client()
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "mark-fixed", "--finding-ids", "F-123,F-456,F-789",
         "--reason", "patch applied", "--yes"],
    )
    assert result.exit_code == 0
    assert "Marked 3/3" in result.output
    assert client.mark_finding_fixed.call_count == 3


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_mark_fixed_default_reason(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client()
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "mark-fixed", "--finding-ids", "F-1", "--yes"],
    )
    assert result.exit_code == 0
    client.mark_finding_fixed.assert_called_once_with("F-1", reason="manually marked")


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_mark_fixed_requires_finding_ids(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client()

    runner = CliRunner()
    result = runner.invoke(cli, ["triage", "mark-fixed", "--yes"])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# interactive
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_interactive_quit_immediately(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "interactive"],
        input="q\n",
    )
    assert result.exit_code == 0
    assert "Done" in result.output


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_interactive_no_findings(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["triage", "interactive"])
    assert result.exit_code == 0
    assert "No findings matched" in result.output


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_interactive_dismiss_action(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client(findings=[_SAMPLE_FINDINGS[0]])
    mock_client_cls.return_value = client

    runner = CliRunner()
    # Select dismiss, provide reason, then quit
    result = runner.invoke(
        cli,
        ["triage", "interactive"],
        input="d\naccepted risk\nq\n",
    )
    assert result.exit_code == 0
    assert "Dismissed" in result.output
    client.dismiss_finding.assert_called_once_with("F-1", reason="accepted risk")


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_interactive_snooze_action(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client(findings=[_SAMPLE_FINDINGS[0]])
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "interactive"],
        input="s\n30d\npatching freeze\nq\n",
    )
    assert result.exit_code == 0
    assert "Snoozed" in result.output
    client.snooze_finding.assert_called_once_with("F-1", until_days=30, reason="patching freeze")


@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_interactive_next_skips_finding(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client = _make_client(findings=_SAMPLE_FINDINGS)
    mock_client_cls.return_value = client

    runner = CliRunner()
    # Skip first, then quit on second
    result = runner.invoke(
        cli,
        ["triage", "interactive"],
        input="n\nq\n",
    )
    assert result.exit_code == 0
    # No lifecycle methods called
    client.dismiss_finding.assert_not_called()
    client.snooze_finding.assert_not_called()


# ---------------------------------------------------------------------------
# Aggregated endpoint filter pass-through
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.triage.AegisClient")
@patch("aegis_cli.commands.triage.load_config")
def test_dismiss_passes_filters_to_aggregated_endpoint(mock_cfg, mock_client_cls):
    """Severity and scanner CSV flags are passed to iter_all_findings as lists."""
    mock_cfg.return_value = _make_cfg()
    client = _make_client(findings=_SAMPLE_FINDINGS)
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "dismiss", "--severity", "critical,high",
         "--scanner", "deps", "--reason", "test", "--yes"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    call_kwargs = client.iter_all_findings.call_args.kwargs
    assert call_kwargs.get("severity") == ["critical", "high"]
    assert call_kwargs.get("scanner") == ["deps"]

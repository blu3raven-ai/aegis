"""Tests for aegis shell interactive REPL command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _invoke_shell(input_text: str):
    """Run 'aegis shell' with the given input fed via stdin."""
    runner = CliRunner(mix_stderr=False)
    return runner.invoke(cli, ["shell"], input=input_text)


# ---------------------------------------------------------------------------
# Basic lifecycle
# ---------------------------------------------------------------------------

def test_shell_help_flag() -> None:
    """aegis shell --help should succeed and describe the command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["shell", "--help"])
    assert result.exit_code == 0
    assert "triage" in result.output.lower() or "interactive" in result.output.lower()


def test_shell_quit_command() -> None:
    r"""'\q' should exit the shell cleanly."""
    result = _invoke_shell(r"\q" + "\n")
    assert result.exit_code == 0
    assert "Bye" in result.output


def test_shell_eof_quits_cleanly() -> None:
    """EOF (Ctrl-D) should exit without a traceback."""
    result = _invoke_shell("")
    assert result.exit_code == 0
    assert "Bye" in result.output


def test_shell_empty_input_is_noop() -> None:
    """Blank lines should be silently skipped, not cause errors."""
    result = _invoke_shell("\n\n\n\\q\n")
    assert result.exit_code == 0
    # Should not contain any traceback or error noise
    assert "Error" not in result.output
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# Built-in meta-commands
# ---------------------------------------------------------------------------

def test_shell_backslash_h_shows_help() -> None:
    r"""'\h' should print the help text."""
    result = _invoke_shell("\\h\n\\q\n")
    assert result.exit_code == 0
    assert "\\h" in result.output or "Show this help" in result.output


def test_shell_backslash_question_shows_no_error_initially() -> None:
    r"""'\?' before any error should report no errors recorded."""
    result = _invoke_shell("\\?\n\\q\n")
    assert result.exit_code == 0
    assert "No errors" in result.output


# ---------------------------------------------------------------------------
# Shorthand expansion
# ---------------------------------------------------------------------------

def test_shell_select_shorthand_invokes_findings_list() -> None:
    """'select critical' should invoke 'findings list --severity critical'."""
    # We patch _run_command inside shell.py to capture the expanded string
    with patch("aegis_cli.commands.shell._run_command") as mock_run:
        mock_run.return_value = None  # no error
        result = _invoke_shell("select critical\n\\q\n")

    assert result.exit_code == 0
    mock_run.assert_called_once_with("findings list --severity critical")


def test_shell_select_expands_any_severity() -> None:
    """'select high' maps to 'findings list --severity high'."""
    with patch("aegis_cli.commands.shell._run_command") as mock_run:
        mock_run.return_value = None
        _invoke_shell("select high\n\\q\n")

    mock_run.assert_called_once_with("findings list --severity high")


def test_shell_view_shorthand_invokes_findings_show() -> None:
    """'view F-123' should invoke 'findings show F-123'."""
    with patch("aegis_cli.commands.shell._run_command") as mock_run:
        mock_run.return_value = None
        result = _invoke_shell("view F-123\n\\q\n")

    assert result.exit_code == 0
    mock_run.assert_called_once_with("findings show F-123")


# ---------------------------------------------------------------------------
# Unknown commands
# ---------------------------------------------------------------------------

def test_shell_unknown_command_prints_helpful_message() -> None:
    """An unrecognised command should surface a useful message, not crash."""
    result = _invoke_shell("notacommand\n\\q\n")
    # The shell should stay alive (exit 0 only from \q) and not raise an exception
    assert result.exit_code == 0
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# Internal helper: _expand_shorthand
# ---------------------------------------------------------------------------

def test_expand_shorthand_select() -> None:
    from aegis_cli.commands.shell import _expand_shorthand

    assert _expand_shorthand("select critical") == "findings list --severity critical"
    assert _expand_shorthand("SELECT high") == "findings list --severity high"


def test_expand_shorthand_view() -> None:
    from aegis_cli.commands.shell import _expand_shorthand

    assert _expand_shorthand("view F-42") == "findings show F-42"


def test_expand_shorthand_passthrough() -> None:
    from aegis_cli.commands.shell import _expand_shorthand

    cmd = "triage dismiss --finding-id F-1 --reason test"
    assert _expand_shorthand(cmd) == cmd


def test_expand_shorthand_empty_string() -> None:
    from aegis_cli.commands.shell import _expand_shorthand

    assert _expand_shorthand("") == ""

"""Tests for aegis completion command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_subprocess_run(stdout: str):
    """Return a patch target that simulates Click emitting a completion script."""
    mock_result = MagicMock()
    mock_result.stdout = stdout
    mock_result.returncode = 0
    mock_result.stderr = ""
    return mock_result


# ---------------------------------------------------------------------------
# Script emission tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion_emits_nonempty_script(shell: str) -> None:
    """Each shell variant should emit a non-empty completion script."""
    fake_script = f"# {shell} completion script for aegis\ncomplete -o default aegis\n"
    runner = CliRunner()

    with patch("subprocess.run", return_value=_fake_subprocess_run(fake_script)):
        result = runner.invoke(cli, ["completion", shell])

    assert result.exit_code == 0, result.output
    assert fake_script in result.output


def test_completion_bash_output() -> None:
    """Bash script is printed verbatim without extra newlines."""
    script = "# bash completion\n_aegis_complete() { :; }\n"
    runner = CliRunner()

    with patch("subprocess.run", return_value=_fake_subprocess_run(script)):
        result = runner.invoke(cli, ["completion", "bash"])

    assert result.exit_code == 0
    assert result.output == script


def test_completion_empty_output_raises_error() -> None:
    """When the subprocess emits no script we surface a clear error."""
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 1
    mock_result.stderr = "something went wrong"
    runner = CliRunner()

    with patch("subprocess.run", return_value=mock_result):
        result = runner.invoke(cli, ["completion", "bash"])

    assert result.exit_code != 0
    assert "Failed to generate bash completion script" in result.output


# ---------------------------------------------------------------------------
# --install flag tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion_install_flag_prints_instructions(shell: str) -> None:
    """--install should print human-readable instructions, not a script."""
    runner = CliRunner()

    # subprocess.run should NOT be called when --install is given
    with patch("subprocess.run") as mock_run:
        result = runner.invoke(cli, ["completion", shell, "--install"])
        mock_run.assert_not_called()

    assert result.exit_code == 0, result.output
    # Instructions always reference the shell name and some shell-specific path
    assert shell in result.output.lower() or "completion" in result.output.lower()


def test_completion_bash_install_references_bashrc() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["completion", "bash", "--install"])
    assert result.exit_code == 0
    assert ".bashrc" in result.output


def test_completion_zsh_install_references_zfunc() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["completion", "zsh", "--install"])
    assert result.exit_code == 0
    assert ".zfunc" in result.output


def test_completion_fish_install_references_fish_completions_dir() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["completion", "fish", "--install"])
    assert result.exit_code == 0
    assert "completions" in result.output


# ---------------------------------------------------------------------------
# Invalid shell rejection
# ---------------------------------------------------------------------------

def test_completion_invalid_shell_rejected() -> None:
    """An unrecognised shell name must be rejected with a non-zero exit."""
    runner = CliRunner()
    result = runner.invoke(cli, ["completion", "powershell"])
    assert result.exit_code != 0
    # Click emits an "Invalid value" message for bad Choice arguments
    assert "Invalid value" in result.output or "Error" in result.output


@pytest.mark.parametrize("bad_shell", ["sh", "csh", "tcsh", "ksh", ""])
def test_completion_unsupported_shells_rejected(bad_shell: str) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["completion", bad_shell])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def test_completion_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["completion", "--help"])
    assert result.exit_code == 0
    assert "bash" in result.output
    assert "zsh" in result.output
    assert "fish" in result.output

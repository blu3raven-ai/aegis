"""aegis shell — interactive triage REPL with persistent history.

Commands recognised inside the shell:
  \\h                            show this help
  \\q  (or Ctrl-D / Ctrl-C)     quit
  \\?                            show last error
  select <severity>             shorthand for: findings list --severity <severity>
  view <id>                     shorthand for: findings show <id>
  <any aegis subcommand>        executed via the aegis CLI
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Optional

import click
from click.testing import CliRunner

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory

    _PROMPT_TOOLKIT = True
except ImportError:
    _PROMPT_TOOLKIT = False

_HISTORY_FILE = Path.home() / ".aegis_history"

_HELP_TEXT = """\
aegis shell — interactive triage REPL
--------------------------------------
\\h                   Show this help
\\q  / Ctrl-D         Quit
\\?                   Show last error

Shorthand commands:
  select <severity>  ->  findings list --severity <severity>
  view <id>          ->  findings show <id>

Any full aegis subcommand is also accepted, e.g.:
  triage dismiss --finding-id F-123 --reason "false positive"
  findings list --severity critical
"""


def _expand_shorthand(line: str) -> str:
    """Rewrite recognised shorthand tokens to full aegis subcommand strings."""
    parts = line.split(None, 1)
    if not parts:
        return line
    keyword = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""

    if keyword == "select":
        return f"findings list --severity {rest}"
    if keyword == "view":
        return f"findings show {rest}"
    return line


def _run_command(args_str: str) -> Optional[str]:
    """Invoke the aegis CLI with *args_str* and return any error message."""
    try:
        tokens = shlex.split(args_str)
    except ValueError as exc:
        return str(exc)

    # Lazy import avoids a circular dependency (main -> shell -> main).
    from aegis_cli.main import cli as aegis_cli  # noqa: PLC0415

    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(aegis_cli, tokens)
    click.echo(result.output, nl=False)
    if result.exit_code != 0:
        return result.output.strip() or "Command failed (no output)"
    return None


@click.command("shell")
def shell() -> None:
    """Interactive triage shell with history and shorthands."""
    click.echo("aegis shell -- type \\h for help, \\q to quit")

    if not _PROMPT_TOOLKIT:
        click.echo(
            "Tip: install prompt-toolkit for richer history & editing:  "
            "pip install prompt_toolkit",
            err=True,
        )

    last_error: Optional[str] = None

    # Build the read-line function once so we share the prompt_toolkit session
    # (and thus its in-process history buffer) across all iterations.
    #
    # prompt_toolkit only works on a real TTY; fall back to plain input() when
    # stdin is piped (e.g. tests, CI, shell scripts).
    import sys
    _use_prompt_toolkit = _PROMPT_TOOLKIT and sys.stdin.isatty()

    if _use_prompt_toolkit:
        pt_session: PromptSession = PromptSession(
            history=FileHistory(str(_HISTORY_FILE))
        )

        def _read_line() -> str:
            return pt_session.prompt("aegis> ")

    else:
        # readline is stdlib on macOS/Linux; import for side-effect (up-arrow history).
        try:
            import readline  # noqa: F401
        except ImportError:
            pass

        def _read_line() -> str:  # type: ignore[misc]
            return input("aegis> ")

    while True:
        try:
            line = _read_line().strip()
        except (EOFError, KeyboardInterrupt):
            click.echo("\nBye.")
            break

        if not line:
            continue

        if line in (r"\q", "quit", "exit"):
            click.echo("Bye.")
            break

        if line == r"\h":
            click.echo(_HELP_TEXT)
            continue

        if line == r"\?":
            if last_error:
                click.echo(f"Last error: {last_error}")
            else:
                click.echo("No errors recorded yet.")
            continue

        expanded = _expand_shorthand(line)
        last_error = _run_command(expanded)

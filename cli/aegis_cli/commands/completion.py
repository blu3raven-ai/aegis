"""aegis completion — emit shell completion scripts.

Usage:
  aegis completion bash    # emit bash completion script
  aegis completion zsh     # emit zsh completion script
  aegis completion fish    # emit fish completion script

Source the output to enable tab-completion in the current shell session,
or follow the --install instructions to make it permanent.
"""

from __future__ import annotations

import os
import subprocess
import sys

import click

_INSTALL_INSTRUCTIONS: dict[str, str] = {
    "bash": """\
# Add aegis tab-completion to bash (permanent):

  aegis completion bash >> ~/.bashrc

Then reload your shell:

  source ~/.bashrc
""",
    "zsh": """\
# Add aegis tab-completion to zsh (permanent):

  mkdir -p ~/.zfunc
  aegis completion zsh > ~/.zfunc/_aegis

Then add the following lines to ~/.zshrc (if not already present):

  fpath=(~/.zfunc $fpath)
  autoload -Uz compinit && compinit

Then reload your shell:

  source ~/.zshrc
""",
    "fish": """\
# Add aegis tab-completion to fish (permanent):

  aegis completion fish > ~/.config/fish/completions/aegis.fish

fish loads completions from that directory automatically — no reload needed.
""",
}


@click.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
@click.option(
    "--install",
    is_flag=True,
    default=False,
    help="Print installation instructions instead of the completion script.",
)
def completion(shell: str, install: bool) -> None:
    """Emit shell completion script. Source the output to enable."""
    if install:
        click.echo(_INSTALL_INSTRUCTIONS[shell], nl=False)
        return

    env = {**os.environ, "_AEGIS_COMPLETE": f"{shell}_source"}
    result = subprocess.run(
        [sys.argv[0]],
        env=env,
        capture_output=True,
        text=True,
    )
    # stdout is the completion script; stderr may contain startup noise we ignore
    if result.stdout:
        click.echo(result.stdout, nl=False)
    else:
        # Re-exec failed (e.g. inside a test harness) — surface the reason so
        # the user knows what went wrong rather than getting silent empty output.
        raise click.ClickException(
            f"Failed to generate {shell} completion script "
            f"(exit {result.returncode}): {result.stderr.strip() or 'no output'}"
        )

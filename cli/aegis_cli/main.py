"""Aegis CLI entry point.

Subcommands:
  init        — initialize a project for Aegis (creates .aegis.yml, policy, .gitignore patch)
  login       — interactive credential setup
  scan        — trigger a vulnerability scan
  status      — check scan run status
  decide      — get a go/no-go decision (CI gate)
  findings    — list open findings
  report      — generate a findings/chains report
  comment     — generate a formatted PR comment from scan findings
  sbom        — export and inspect SBOMs
  triage      — bulk finding lifecycle operations (dismiss, snooze, assign, mark-fixed)
  export      — export findings as CSV or JSONL for offline analysis
  completion  — emit shell completion script (bash/zsh/fish)
  shell       — interactive triage REPL with history
  watch       — live-tail finding events from the SSE event bus
"""

from __future__ import annotations

import click

from aegis_cli import __version__
from aegis_cli.commands.init import init_cmd
from aegis_cli.commands.login import login
from aegis_cli.commands.scan import scan_cmd
from aegis_cli.commands.status import status_cmd
from aegis_cli.commands.decide import decide_cmd
from aegis_cli.commands.findings import findings_cmd
from aegis_cli.commands.mcp_serve import mcp_serve
from aegis_cli.commands.report import report
from aegis_cli.commands.comment import comment_cmd
from aegis_cli.commands.sbom import sbom_group
from aegis_cli.commands.triage import triage_group
from aegis_cli.commands.export import export_group
from aegis_cli.commands.completion import completion
from aegis_cli.commands.shell import shell
from aegis_cli.commands.kev import kev_group
from aegis_cli.commands.epss import epss_group
from aegis_cli.commands.watch import watch_cmd


@click.group()
@click.version_option(version=__version__, prog_name="aegis")
def cli() -> None:
    """Aegis — vulnerability scanner CLI for CI/CD and local development.

    Configuration (env takes priority over config file):
    \b
      AEGIS_BASE_URL     Backend URL (default: https://aegis.example.org)
      AEGIS_API_TOKEN    API authentication token
      AEGIS_DEFAULT_ORG  Default organisation name

    Config file: ~/.aegis/config.toml
    Credentials: ~/.aegis/credentials  (bare token, one per line)
    """


cli.add_command(init_cmd)
cli.add_command(login)
cli.add_command(scan_cmd)
cli.add_command(status_cmd)
cli.add_command(decide_cmd)
cli.add_command(findings_cmd)
cli.add_command(mcp_serve)
cli.add_command(report)
cli.add_command(comment_cmd)
cli.add_command(sbom_group)
cli.add_command(triage_group)
cli.add_command(export_group)
cli.add_command(completion)
cli.add_command(shell)
cli.add_command(kev_group)
cli.add_command(epss_group)
cli.add_command(watch_cmd)

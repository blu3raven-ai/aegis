"""aegis status — show progress and findings for a scan run."""

from __future__ import annotations

import sys

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config
from aegis_cli.output import console, err_console, format_scan_status


@click.command("status")
@click.argument("scan_id")
@click.option("--org", default=None, help="Organisation name (overrides AEGIS_DEFAULT_ORG).")
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output result as JSON.",
)
def status_cmd(scan_id: str, org: str | None, output_json: bool) -> None:
    """Show progress and summary for a scan run identified by SCAN_ID."""
    cfg = load_config()
    resolved_org = org or cfg.default_org
    if not resolved_org:
        err_console.print(
            "[bold red]Error:[/bold red] No org specified. "
            "Pass --org or set AEGIS_DEFAULT_ORG."
        )
        sys.exit(1)
    if not cfg.api_token:
        err_console.print(
            "[bold red]Error:[/bold red] No API token. Set AEGIS_API_TOKEN."
        )
        sys.exit(1)

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            run = client.get_scan_status(scan_id, org=resolved_org)
        except AegisAPIError as exc:
            if exc.status_code == 404:
                err_console.print(
                    f"[bold red]Not found:[/bold red] No run with id '{scan_id}' "
                    f"for org '{resolved_org}'."
                )
            else:
                err_console.print(f"[bold red]Error:[/bold red] {exc}")
            sys.exit(1)

    if output_json:
        import json as _json
        console.print_json(_json.dumps(run, default=str))
        return

    console.print(format_scan_status(run), end="")

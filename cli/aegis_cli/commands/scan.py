"""aegis scan — trigger a vulnerability scan for the current or specified repo."""

from __future__ import annotations

import sys
import time

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config
from aegis_cli.output import console, err_console, format_scan_status

_POLL_INTERVAL = 3  # seconds between status polls when --wait is given


@click.command("scan")
@click.option(
    "--scanner",
    default="dependencies",
    show_default=True,
    help="Scanner to run: dependencies, code_scanning, secrets, containers.",
)
@click.option("--org", default=None, help="Organisation name (overrides AEGIS_DEFAULT_ORG).")
@click.option("--repo", default=None, help="Hint: filter scan to this repo (org/name).")
@click.option(
    "--wait",
    is_flag=True,
    default=False,
    help="Block until the scan completes and print findings.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output result as JSON.",
)
def scan_cmd(
    scanner: str,
    org: str | None,
    repo: str | None,
    wait: bool,
    output_json: bool,
) -> None:
    """Trigger a vulnerability scan for an organisation.

    Detects the current repo from the environment when --repo is omitted.
    In CI/CD set AEGIS_DEFAULT_ORG so --org can be omitted too.
    """
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
            "[bold red]Error:[/bold red] No API token found. "
            "Set AEGIS_API_TOKEN or write to ~/.aegis/credentials."
        )
        sys.exit(1)

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            result = client.trigger_scan(
                org=resolved_org,
                scanner_type=scanner,
                repo=repo,
            )
        except AegisAPIError as exc:
            err_console.print(f"[bold red]Scan trigger failed:[/bold red] {exc}")
            sys.exit(1)

        if output_json:
            import json as _json
            console.print_json(_json.dumps(result))
            return

        runs = result.get("runs", [])
        msg = result.get("message", "")
        console.print(f"[bold green]Scan queued.[/bold green]  {msg}")
        for r in runs:
            console.print(f"  org={r.get('org')}  queued={r.get('queued')}")

        if not wait:
            return

        # Poll until the latest run for this org finishes.
        console.print("[dim]Waiting for scan to complete…[/dim]")
        _wait_for_completion(client, org=resolved_org, scanner_type=scanner)


def _wait_for_completion(
    client: AegisClient, *, org: str, scanner_type: str
) -> None:
    """Poll run status until non-running state, then print summary."""
    active_statuses = {"queued", "running", "ingesting"}
    for _ in range(300):  # cap at 300 * 3s = 15 min
        try:
            data = client.get_latest_run(org=org, scanner_type=scanner_type)
        except AegisAPIError as exc:
            err_console.print(f"[yellow]Status poll error:[/yellow] {exc}")
            time.sleep(_POLL_INTERVAL)
            continue

        run = data.get("latest")
        if not run:
            console.print("[dim]No active run found.[/dim]")
            return

        status = run.get("status", "")
        pct = (run.get("progress") or {}).get("percent", 0)
        console.print(f"  status={status}  progress={pct}%", end="\r")

        if status not in active_statuses:
            console.print()  # newline after \r updates
            console.print(format_scan_status(run), end="")
            return

        time.sleep(_POLL_INTERVAL)

    err_console.print("[yellow]Timed out waiting for scan completion.[/yellow]")
    sys.exit(1)

"""aegis watch — live-tail of finding events from the SSE event bus."""

from __future__ import annotations

import sys

import click
import httpx

from aegis_cli.config import load_config
from aegis_cli.output import console, err_console
from aegis_cli.sse_client import stream_events
from aegis_cli.watch_formatters import (
    FINDING_EVENT_TYPES,
    format_json,
    format_pretty,
    matches_filters,
)


def _parse_csv_option(value: str | None) -> set[str] | None:
    if value is None:
        return None
    items = {v.strip().lower() for v in value.split(",") if v.strip()}
    return items or None


@click.command("watch")
@click.option(
    "--severity",
    default=None,
    help="Comma-separated severity filter: critical,high,medium,low.",
)
@click.option(
    "--scanner",
    default=None,
    help="Comma-separated scanner filter: dependencies,code_scanning,secrets,containers.",
)
@click.option(
    "--org",
    "orgs",
    default=None,
    help="Comma-separated org filter (multi-org installs).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Emit one JSON object per line instead of pretty output.",
)
def watch_cmd(
    severity: str | None,
    scanner: str | None,
    orgs: str | None,
    output_json: bool,
) -> None:
    """Stream finding events live from the Aegis SSE event bus.

    Connects to /events/api/stream and prints one line per finding
    event as it arrives.  Press Ctrl-C to exit.

    Filter flags are case-insensitive and accept comma-separated values:

    \b
      aegis watch --severity critical,high
      aegis watch --scanner secrets,sast
      aegis watch --org example-org
      aegis watch --json | jq .
    """
    cfg = load_config()
    if not cfg.api_token:
        err_console.print(
            "[bold red]Error:[/bold red] No API token. Set AEGIS_API_TOKEN."
        )
        sys.exit(1)

    severities = _parse_csv_option(severity)
    scanners = _parse_csv_option(scanner)
    org_filter = _parse_csv_option(orgs)

    if not output_json:
        console.print(
            f"[dim]Watching {cfg.base_url} for finding events… (Ctrl-C to exit)[/dim]"
        )

    try:
        for message in stream_events(cfg.base_url, cfg.api_token):
            if message.event_type not in FINDING_EVENT_TYPES:
                continue
            if not matches_filters(
                message.event_type,
                message.data,
                severities=severities,
                scanners=scanners,
                orgs=org_filter,
            ):
                continue
            if output_json:
                click.echo(format_json(message.event_type, message.data))
            else:
                console.print(format_pretty(message.event_type, message.data))
    except KeyboardInterrupt:
        if not output_json:
            console.print("\n[dim]Disconnected.[/dim]")
        return
    except httpx.HTTPStatusError as exc:
        err_console.print(
            f"[bold red]SSE error:[/bold red] {exc.response.status_code} {exc.response.reason_phrase}"
        )
        sys.exit(1)
    except httpx.RequestError as exc:
        err_console.print(f"[bold red]Connection error:[/bold red] {exc}")
        sys.exit(1)

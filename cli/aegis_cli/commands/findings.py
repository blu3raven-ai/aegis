"""aegis findings — list open findings for an organisation."""

from __future__ import annotations

import sys

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config
from aegis_cli.output import (
    console,
    err_console,
    format_findings_table,
    format_findings_json,
)


@click.command("findings")
@click.option("--org", default=None, help="Organisation name (overrides AEGIS_DEFAULT_ORG).")
@click.option("--repo", default=None, help="Filter by repository substring (org/name).")
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
    "--state",
    default=None,
    help="Comma-separated state filter: open,closed,dismissed,fixed.",
)
@click.option(
    "--q",
    default=None,
    help="Free-text search across title/cve/package/path (server-side ILIKE).",
)
@click.option(
    "--cve",
    default=None,
    help="Exact CVE id match (e.g. CVE-2021-44228).",
)
@click.option(
    "--sort",
    default=None,
    type=click.Choice(["severity", "created_at", "updated_at"], case_sensitive=False),
    help="Sort key (default: severity).",
)
@click.option(
    "--direction",
    default=None,
    type=click.Choice(["asc", "desc"], case_sensitive=False),
    help="Sort direction (default: desc).",
)
@click.option(
    "--limit",
    default=None,
    type=click.IntRange(1, 200),
    help="Page size, 1..200 (default: 50).",
)
@click.option(
    "--cursor",
    default=None,
    help="Opaque cursor from a previous response's next_cursor.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def findings_cmd(
    org: str | None,
    repo: str | None,
    severity: str | None,
    scanner: str | None,
    state: str | None,
    q: str | None,
    cve: str | None,
    sort: str | None,
    direction: str | None,
    limit: int | None,
    cursor: str | None,
    output_json: bool,
) -> None:
    """List vulnerability findings for an organisation.

    Calls the aggregated ``GET /api/v1/findings`` endpoint — one request,
    server-side filtering, cursor pagination. Pass --json for machine-readable
    output suitable for piping into jq or saving to CI artefacts.
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
            "[bold red]Error:[/bold red] No API token. Set AEGIS_API_TOKEN."
        )
        sys.exit(1)

    severity_list = [s.strip() for s in severity.split(",") if s.strip()] if severity else None
    scanner_list = [s.strip() for s in scanner.split(",") if s.strip()] if scanner else None
    state_list = [s.strip() for s in state.split(",") if s.strip()] if state else None

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            response = client.list_findings(
                org=resolved_org,
                severity=severity_list,
                scanner=scanner_list,
                state=state_list,
                q=q,
                cve=cve,
                sort=sort,
                direction=direction,
                limit=limit,
                cursor=cursor,
            )
        except AegisAPIError as exc:
            err_console.print(f"[bold red]Findings error:[/bold red] {exc}")
            sys.exit(1)

    items = response.get("findings", []) or []
    next_cursor = response.get("next_cursor")
    total_count = response.get("total_count")

    # The endpoint exposes substring search via `q` (which also matches title,
    # cve, etc.) but no dedicated repo-only filter. Keep `--repo` as a precise
    # client-side filter so users do not have to pull broader q matches.
    if repo:
        items = [f for f in items if repo in (f.get("repo") or "")]

    if output_json:
        console.print(format_findings_json(items))
        return

    console.print(format_findings_table(items), end="")
    if total_count is not None and total_count > len(items):
        console.print(
            f"[dim]Showing {len(items)} of {total_count} finding(s)[/dim]"
        )
    else:
        console.print(f"[dim]Total: {len(items)} finding(s)[/dim]")
    if next_cursor:
        console.print(f"[dim]Next page: --cursor {next_cursor}[/dim]")

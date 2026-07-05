"""aegis report — generate a Markdown/HTML/JSON findings report."""
from __future__ import annotations

import sys
from pathlib import Path

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config
from aegis_cli.report_formatters import format_html, format_json, format_markdown


@click.command("report")
@click.option("--repo", default=None, help="Scope report to a single repository (org/name).")
@click.option("--chain-id", default=None, help="Scope report to a single attack chain.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["markdown", "html", "json"]),
    default="markdown",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write report to file instead of stdout.",
)
@click.option(
    "--since",
    default="7d",
    show_default=True,
    help="Time window: e.g. 7d, 30d, 90d.",
)
@click.option(
    "--severity",
    default=None,
    help="Comma-separated severity filter: critical,high,medium,low.",
)
@click.option(
    "--org",
    default=None,
    help="Organisation name (overrides AEGIS_DEFAULT_ORG).",
)
def report(
    repo: str | None,
    chain_id: str | None,
    fmt: str,
    output: Path | None,
    since: str,
    severity: str | None,
    org: str | None,
) -> None:
    """Generate an Aegis findings/chains report.

    Without options, produces an org-level Markdown summary to stdout.
    Use --output to write to a file; --format for html or json output.
    """
    cfg = load_config()
    resolved_org = org or cfg.default_org or ""

    if not cfg.api_token:
        click.echo(
            "Error: No API token found. Set AEGIS_API_TOKEN or run `aegis login`.",
            err=True,
        )
        sys.exit(1)

    severities = [s.strip() for s in severity.split(",")] if severity else None

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            body = _build_report_body(
                client=client,
                org=resolved_org,
                repo=repo,
                chain_id=chain_id,
                since=since,
                severities=severities,
            )
        except AegisAPIError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    if fmt == "markdown":
        text = format_markdown(body)
    elif fmt == "html":
        text = format_html(body)
    else:
        text = format_json(body)

    if output:
        output.write_text(text, encoding="utf-8")
        click.echo(f"Report written to {output}")
    else:
        click.echo(text)


def _build_report_body(
    *,
    client: AegisClient,
    org: str,
    repo: str | None,
    chain_id: str | None,
    since: str,
    severities: list[str] | None,
) -> dict:
    """Fetch data from the backend and assemble the report body dict."""
    body: dict = {"since": since}

    if chain_id:
        chain = client.get_chain(org=org, chain_id=chain_id)
        body["chain"] = chain
        body["org"] = org
        return body

    findings = client.iter_all_findings(org=org, severity=severities)

    if repo:
        findings = [f for f in findings if repo in (f.get("repo") or "")]
        body["repo"] = repo
    body["org"] = org
    body["findings"] = findings
    return body

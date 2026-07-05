"""aegis epss — FIRST.org EPSS commands.

Subcommands:
  score <CVE-ID>    — Show the EPSS score + percentile for a CVE
  top --limit N     — List open findings in the org ranked by EPSS score
  refresh           — Trigger an immediate EPSS feed refresh (admin)
"""
from __future__ import annotations

import click

from aegis_cli.client import AegisAPIError, AegisClient
from aegis_cli.config import load_config


@click.group("epss")
def epss_group() -> None:
    """FIRST.org EPSS (Exploit Prediction Scoring System) commands."""


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------


@epss_group.command()
@click.argument("cve_id")
def score(cve_id: str) -> None:
    """Show EPSS score and percentile for a single CVE (e.g. CVE-2024-12345)."""
    cfg = load_config()
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    try:
        data = client.get_epss_score(cve_id)
    except AegisAPIError as exc:
        if exc.status_code == 404:
            raise click.ClickException(f"{cve_id} is not in the EPSS feed.") from exc
        raise click.ClickException(str(exc)) from exc

    score_value = data.get("score", 0.0) or 0.0
    percentile = data.get("percentile", 0.0) or 0.0

    click.echo("")
    click.echo(f"CVE:           {data.get('cve', '')}")
    click.echo(f"EPSS score:    {score_value:.5f}  ({score_value * 100:.2f}%)")
    click.echo(f"Percentile:    {percentile:.5f}  (top {(1 - percentile) * 100:.2f}%)")
    click.echo(f"Scored date:   {data.get('scored_date', '')}")
    click.echo(f"Fetched at:    {data.get('fetched_at', '')}")
    click.echo("")


# ---------------------------------------------------------------------------
# top
# ---------------------------------------------------------------------------


@epss_group.command()
@click.option("--org", default=None, envvar="AEGIS_DEFAULT_ORG", help="Organisation name.")
@click.option("--limit", default=20, show_default=True, help="Max findings to return.")
def top(org: str | None, limit: int) -> None:
    """List open findings in the org ranked by EPSS score, descending."""
    cfg = load_config()
    effective_org = org or cfg.default_org or ""
    if not effective_org:
        raise click.UsageError("Specify --org or set AEGIS_DEFAULT_ORG.")

    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)
    try:
        result = client.get_epss_top(org_id=effective_org, limit=limit)
    except AegisAPIError as exc:
        raise click.ClickException(str(exc)) from exc

    findings = result.get("findings", [])
    count = result.get("count", len(findings))

    click.echo("")
    click.echo(f"Top findings by EPSS for {effective_org} ({count} shown)")
    click.echo("─" * 70)

    if not findings:
        click.echo("  No open findings match a scored CVE.")
        click.echo("")
        return

    click.echo(f"  {'EPSS':>7}  {'%ile':>6}  {'CVE':<18}  {'SEV':<8}  {'TOOL':<10}  REPO")
    for f in findings:
        s = f.get("epss_score", 0.0) or 0.0
        p = f.get("epss_percentile", 0.0) or 0.0
        cve = f.get("cve", "")
        sev = (f.get("severity") or "").lower()
        tool = f.get("tool", "")
        repo = f.get("repo", "") or "—"

        line = f"  {s:>7.4f}  {p:>6.3f}  {cve:<18}  {sev:<8}  {tool:<10}  {repo}"
        if s >= 0.7:
            click.echo(click.style(line, fg="red"))
        elif s >= 0.3:
            click.echo(click.style(line, fg="yellow"))
        else:
            click.echo(line)

    click.echo("")


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------


@epss_group.command()
def refresh() -> None:
    """Trigger an immediate EPSS feed refresh (admin)."""
    cfg = load_config()
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    try:
        result = client.trigger_epss_refresh()
    except AegisAPIError as exc:
        raise click.ClickException(str(exc)) from exc

    fetched = result.get("fetched", 0)
    new = result.get("new", 0)

    click.echo("")
    click.echo(f"EPSS refresh complete: {fetched:,} rows fetched, {new:,} new.")
    click.echo("")

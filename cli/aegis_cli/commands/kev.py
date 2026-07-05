"""aegis kev — CISA Known Exploited Vulnerabilities commands.

Subcommands:
  exposure          — Show KEV overlap with the org's open findings
  show <CVE-ID>     — Show a single KEV catalog entry
  recent --days N   — Recent additions to the catalog
"""
from __future__ import annotations

import click

from aegis_cli.client import AegisAPIError, AegisClient
from aegis_cli.config import load_config


def _warn(text: str) -> str:
    """Prefix with warning marker for overdue/ransomware items."""
    return f"  ⚠  {text}"


def _bullet(text: str) -> str:
    return f"  ● {text}"


@click.group("kev")
def kev_group() -> None:
    """CISA Known Exploited Vulnerabilities catalog commands."""


# ---------------------------------------------------------------------------
# exposure
# ---------------------------------------------------------------------------

@kev_group.command()
@click.option("--org", default=None, envvar="AEGIS_DEFAULT_ORG", help="Organisation name.")
def exposure(org: str | None) -> None:
    """Show CISA KEV exposure summary for the org."""
    cfg = load_config()
    effective_org = org or cfg.default_org or ""
    if not effective_org:
        raise click.UsageError("Specify --org or set AEGIS_DEFAULT_ORG.")

    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)
    try:
        summary = client.get_kev_exposure_summary(effective_org)
    except AegisAPIError as exc:
        raise click.ClickException(str(exc)) from exc

    total = summary.get("open_findings_total", 0)
    in_kev = summary.get("open_findings_in_kev", 0)
    overdue = summary.get("kev_overdue", 0)
    ransomware = summary.get("kev_with_ransomware", 0)
    top_findings = summary.get("top_kev_findings", [])

    pct = f"({in_kev / total * 100:.1f}%)" if total > 0 else ""

    click.echo("")
    click.echo("CISA KEV Exposure Summary")
    click.echo("─" * 41)
    click.echo(f"Total open findings:      {total:>8,}")
    click.echo(f"Findings hitting KEV:     {in_kev:>8,}  {pct}")

    overdue_line = f"Past CISA due date:       {overdue:>8,}"
    if overdue > 0:
        click.echo(click.style(overdue_line + "  ⚠", fg="yellow"))
    else:
        click.echo(overdue_line)

    click.echo(f"Ransomware-associated:    {ransomware:>8,}")
    click.echo("")

    if top_findings:
        click.echo("Top KEV findings:")
        for f in top_findings:
            cve = f.get("cve_id", "")
            name = f.get("vulnerability_name") or ""
            count = f.get("finding_count", 0)
            due = f.get("due_date") or ""
            is_ransomware = f.get("known_ransomware_use", False)

            suffix_parts = []
            if due:
                suffix_parts.append(f"due {due}")
            if is_ransomware:
                suffix_parts.append("RANSOMWARE")
            suffix = "  · " + "  · ".join(suffix_parts) if suffix_parts else ""

            line = f"  ● {cve} ({count:>2} findings)  {name}{suffix}"
            if is_ransomware:
                click.echo(click.style(line, fg="red"))
            else:
                click.echo(line)

    click.echo("")
    click.echo("Run `aegis kev show <cve>` for entry details.")


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

@kev_group.command()
@click.argument("cve_id")
def show(cve_id: str) -> None:
    """Show details for a single KEV entry (e.g. CVE-2024-12345)."""
    cfg = load_config()
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    try:
        entry = client.get_kev_entry(cve_id)
    except AegisAPIError as exc:
        if exc.status_code == 404:
            raise click.ClickException(f"{cve_id} is not in the CISA KEV catalog.") from exc
        raise click.ClickException(str(exc)) from exc

    ransomware_str = (
        "Yes" if entry.get("known_ransomware_use") is True
        else "No" if entry.get("known_ransomware_use") is False
        else "Unknown"
    )

    click.echo("")
    click.echo(f"CVE ID:            {entry.get('cve_id', '')}")
    click.echo(f"Vendor / Project:  {entry.get('vendor_project', '')}")
    click.echo(f"Product:           {entry.get('product', '')}")
    click.echo(f"Name:              {entry.get('vulnerability_name', '')}")
    click.echo(f"Date Added:        {entry.get('date_added', '')}")
    click.echo(f"Due Date:          {entry.get('due_date', '')}")
    click.echo(f"Ransomware Use:    {ransomware_str}")
    click.echo(f"CWEs:              {', '.join(entry.get('cwes') or []) or 'N/A'}")
    click.echo("")
    click.echo("Description:")
    click.echo(f"  {entry.get('short_description', '')}")
    click.echo("")
    click.echo("Required Action:")
    click.echo(f"  {entry.get('required_action', '')}")
    if entry.get("notes"):
        click.echo("")
        click.echo(f"Notes:  {entry['notes']}")
    click.echo("")


# ---------------------------------------------------------------------------
# recent
# ---------------------------------------------------------------------------

@kev_group.command()
@click.option("--days", default=30, show_default=True, help="Window in days.")
def recent(days: int) -> None:
    """Show recent additions to the CISA KEV catalog."""
    cfg = load_config()
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    try:
        result = client.get_kev_recent(days=days)
    except AegisAPIError as exc:
        raise click.ClickException(str(exc)) from exc

    entries = result.get("entries", [])
    count = result.get("count", len(entries))

    click.echo("")
    click.echo(f"Recent KEV Additions (last {days} days): {count} entries")
    click.echo("─" * 50)

    if not entries:
        click.echo("  No new entries in this window.")
    else:
        for e in entries:
            ransomware_badge = "  [RANSOMWARE]" if e.get("known_ransomware_use") else ""
            click.echo(
                f"  {e.get('date_added', ''):>12}  {e.get('cve_id', ''):<22}"
                f"  {e.get('vulnerability_name', '')}{ransomware_badge}"
            )

    click.echo("")

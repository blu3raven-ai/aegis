"""aegis triage — bulk finding lifecycle operations from the CLI.

Subcommands:
  dismiss     — dismiss findings matching filters
  snooze      — snooze findings for a duration
  assign      — assign findings to a user
  mark-fixed  — mark findings as manually fixed
  interactive — walk through findings one-by-one
"""

from __future__ import annotations

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config
from aegis_cli.triage_helpers import (
    apply_filters,
    confirm_bulk_action,
    parse_duration,
    parse_finding_ids,
)


def _split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _resolve_targets(
    client: AegisClient,
    org: str,
    finding_ids: str | None,
    severity: str | None,
    scanner: str | None,
    since: str | None,
) -> list[str]:
    """Return a list of finding IDs to act on.

    If --finding-ids is given, use those directly.  Otherwise, query the
    backend and apply client-side filters.
    """
    if finding_ids:
        return parse_finding_ids(finding_ids)

    all_findings = client.iter_all_findings(
        org=org,
        severity=_split_csv(severity),
        scanner=_split_csv(scanner),
    )
    return apply_filters(all_findings, since=since)


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------

@click.group("triage")
def triage_group() -> None:
    """Bulk finding triage operations."""


# ---------------------------------------------------------------------------
# dismiss
# ---------------------------------------------------------------------------

@triage_group.command()
@click.option("--finding-ids", default=None, help="Comma-separated finding IDs (e.g. F-1,F-2).")
@click.option(
    "--severity",
    default=None,
    help="Comma-separated severities to filter by (critical,high,medium,low).",
)
@click.option(
    "--scanner",
    default=None,
    help="Comma-separated scanner types (deps,sast,secrets,containers).",
)
@click.option("--since", default=None, help="Only findings older than this (e.g. 30d, 90d).")
@click.option("--reason", required=True, help="Audit-friendly reason for dismissal.")
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation prompt.")
@click.option("--org", default=None, envvar="AEGIS_DEFAULT_ORG", help="Organisation name.")
def dismiss(
    finding_ids: str | None,
    severity: str | None,
    scanner: str | None,
    since: str | None,
    reason: str,
    yes: bool,
    org: str | None,
) -> None:
    """Dismiss findings matching filters."""
    cfg = load_config()
    effective_org = org or cfg.default_org or ""
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    targets = _resolve_targets(client, effective_org, finding_ids, severity, scanner, since)
    if not targets:
        click.echo("No findings matched.")
        return

    if not yes and not confirm_bulk_action(targets, action="dismiss"):
        click.echo("Aborted.")
        return

    success = 0
    for fid in targets:
        try:
            client.dismiss_finding(fid, reason=reason)
            success += 1
        except Exception as exc:
            click.echo(f"  x {fid}: {exc}", err=True)

    click.echo(f"Dismissed {success}/{len(targets)} findings.")


# ---------------------------------------------------------------------------
# snooze
# ---------------------------------------------------------------------------

@triage_group.command()
@click.option("--finding-ids", default=None, help="Comma-separated finding IDs.")
@click.option("--severity", default=None, help="Comma-separated severities.")
@click.option("--scanner", default=None, help="Comma-separated scanner types.")
@click.option(
    "--until",
    required=True,
    help="Snooze duration from today (e.g. 30d, 1w).",
)
@click.option("--reason", required=True, help="Reason for snooze (recorded in audit log).")
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation prompt.")
@click.option("--org", default=None, envvar="AEGIS_DEFAULT_ORG", help="Organisation name.")
def snooze(
    finding_ids: str | None,
    severity: str | None,
    scanner: str | None,
    until: str,
    reason: str,
    yes: bool,
    org: str | None,
) -> None:
    """Snooze findings until the given duration elapses."""
    cfg = load_config()
    effective_org = org or cfg.default_org or ""
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    until_days = parse_duration(until)
    targets = _resolve_targets(client, effective_org, finding_ids, severity, scanner, None)
    if not targets:
        click.echo("No findings matched.")
        return

    if not yes and not confirm_bulk_action(targets, action="snooze"):
        click.echo("Aborted.")
        return

    success = 0
    for fid in targets:
        try:
            client.snooze_finding(fid, until_days=until_days, reason=reason)
            success += 1
        except Exception as exc:
            click.echo(f"  x {fid}: {exc}", err=True)

    click.echo(f"Snoozed {success}/{len(targets)} findings for {until_days} day(s).")


# ---------------------------------------------------------------------------
# assign
# ---------------------------------------------------------------------------

@triage_group.command()
@click.option("--finding-ids", default=None, help="Comma-separated finding IDs.")
@click.option("--severity", default=None, help="Comma-separated severities.")
@click.option("--scanner", default=None, help="Comma-separated scanner types.")
@click.option("--to", "assignee", required=True, help="Assignee email address.")
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation prompt.")
@click.option("--org", default=None, envvar="AEGIS_DEFAULT_ORG", help="Organisation name.")
def assign(
    finding_ids: str | None,
    severity: str | None,
    scanner: str | None,
    assignee: str,
    yes: bool,
    org: str | None,
) -> None:
    """Assign findings to a user."""
    cfg = load_config()
    effective_org = org or cfg.default_org or ""
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    targets = _resolve_targets(client, effective_org, finding_ids, severity, scanner, None)
    if not targets:
        click.echo("No findings matched.")
        return

    if not yes and not confirm_bulk_action(targets, action=f"assign to {assignee}"):
        click.echo("Aborted.")
        return

    success = 0
    for fid in targets:
        try:
            client.assign_finding(fid, assignee=assignee)
            success += 1
        except Exception as exc:
            click.echo(f"  x {fid}: {exc}", err=True)

    click.echo(f"Assigned {success}/{len(targets)} findings to {assignee}.")


# ---------------------------------------------------------------------------
# mark-fixed
# ---------------------------------------------------------------------------

@triage_group.command(name="mark-fixed")
@click.option("--finding-ids", required=True, help="Comma-separated finding IDs.")
@click.option(
    "--reason",
    default="manually marked",
    show_default=True,
    help="Reason recorded in the audit log.",
)
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation prompt.")
def mark_fixed(finding_ids: str, reason: str, yes: bool) -> None:
    """Mark specific findings as fixed."""
    cfg = load_config()
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    targets = parse_finding_ids(finding_ids)
    if not targets:
        click.echo("No finding IDs provided.")
        return

    if not yes and not confirm_bulk_action(targets, action="mark-fixed"):
        click.echo("Aborted.")
        return

    success = 0
    for fid in targets:
        try:
            client.mark_finding_fixed(fid, reason=reason)
            success += 1
        except Exception as exc:
            click.echo(f"  x {fid}: {exc}", err=True)

    click.echo(f"Marked {success}/{len(targets)} findings as fixed.")


# ---------------------------------------------------------------------------
# interactive
# ---------------------------------------------------------------------------

@triage_group.command()
@click.option("--severity", default=None, help="Comma-separated severities to filter by.")
@click.option("--scanner", default=None, help="Comma-separated scanner types.")
@click.option("--org", default=None, envvar="AEGIS_DEFAULT_ORG", help="Organisation name.")
def interactive(severity: str | None, scanner: str | None, org: str | None) -> None:
    """Walk through matching findings one-by-one and prompt for an action on each."""
    cfg = load_config()
    effective_org = org or cfg.default_org or ""
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    findings = client.iter_all_findings(
        org=effective_org,
        severity=_split_csv(severity),
        scanner=_split_csv(scanner),
    )

    if not findings:
        click.echo("No findings matched.")
        return

    click.echo(f"Reviewing {len(findings)} finding(s). Enter 'q' at any time to quit.\n")

    for f in findings:
        click.echo("\n" + "-" * 60)
        click.echo(
            f"[{(f.get('severity') or (f.get('security_advisory') or {}).get('severity', '?')).upper()}]"
            f" {f.get('title') or (f.get('security_advisory') or {}).get('summary', '(no title)')}"
            f" ({f.get('id') or f.get('number', '?')})"
        )
        repo = f.get("repo") or (f.get("repository") or {}).get("full_name", "")
        file_path = f.get("filePath") or f.get("file_path") or f.get("path", "")
        line = f.get("line", "?")
        if repo or file_path:
            click.echo(f"  Repo: {repo}  {file_path}:{line}")

        action = click.prompt(
            "Action? [d]ismiss / [s]nooze / [a]ssign / [f]ixed / [n]ext / [q]uit",
            type=click.Choice(["d", "s", "a", "f", "n", "q"], case_sensitive=False),
            default="n",
        )

        fid = str(f.get("id") or f.get("number") or "")
        if not fid:
            click.echo("  (cannot act — finding has no ID)", err=True)
            continue

        if action == "q":
            break
        elif action == "n":
            continue
        elif action == "d":
            reason = click.prompt("  Dismissal reason")
            try:
                client.dismiss_finding(fid, reason=reason)
                click.echo("  Dismissed.")
            except AegisAPIError as exc:
                click.echo(f"  x {exc}", err=True)
        elif action == "s":
            until_raw = click.prompt("  Snooze until (e.g. 30d)", default="30d")
            reason = click.prompt("  Reason")
            try:
                client.snooze_finding(fid, until_days=parse_duration(until_raw), reason=reason)
                click.echo("  Snoozed.")
            except (AegisAPIError, ValueError) as exc:
                click.echo(f"  x {exc}", err=True)
        elif action == "a":
            assignee = click.prompt("  Assignee email")
            try:
                client.assign_finding(fid, assignee=assignee)
                click.echo("  Assigned.")
            except AegisAPIError as exc:
                click.echo(f"  x {exc}", err=True)
        elif action == "f":
            reason = click.prompt("  Reason", default="manually marked")
            try:
                client.mark_finding_fixed(fid, reason=reason)
                click.echo("  Marked fixed.")
            except AegisAPIError as exc:
                click.echo(f"  x {exc}", err=True)

    click.echo("\nDone.")

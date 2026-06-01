"""aegis export — download Aegis data for offline analysis.

Subcommands:
  findings   — export all findings matching filters as CSV or JSONL

Examples:
    aegis export findings --format csv -o findings.csv --severity critical,high
    aegis export findings --format json -o findings.jsonl --repo-id example-org/api
    aegis export findings --format csv -o findings.csv --since 30d
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config


def _parse_since_param(since: str | None) -> str | None:
    """Convert a duration string like '30d' or '90d' into an ISO-8601 cutoff.

    Only day-based durations are supported (e.g. 30d, 90d).  Returns None if
    since is None or cannot be parsed, so the server applies no time filter.
    """
    if not since:
        return None
    stripped = since.strip()
    if stripped.lower().endswith("d"):
        try:
            days = int(stripped[:-1])
        except ValueError:
            return None
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return cutoff.isoformat()
    # Return as-is (assumed to already be ISO-8601 or unsupported)
    return stripped


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------

@click.group("export")
def export_group() -> None:
    """Export Aegis data for offline analysis."""


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

@export_group.command("findings")
@click.option(
    "-f", "--format",
    "fmt",
    type=click.Choice(["csv", "json"]),
    default="csv",
    show_default=True,
    help="Output format.  csv produces a spreadsheet-ready file; json produces JSONL.",
)
@click.option(
    "-o", "--output",
    required=True,
    type=click.Path(dir_okay=False, writable=True),
    help="Destination file path (e.g. findings.csv or findings.jsonl).",
)
@click.option("--severity", default=None, help="Comma-separated severities (critical,high,medium,low).")
@click.option("--scanner", default=None, help="Comma-separated scanner types (e.g. dependencies,secrets).")
@click.option("--status", default=None, help="Comma-separated finding states (open,fixed,dismissed).")
@click.option("--repo-id", default=None, help="Restrict to a single repository (owner/name).")
@click.option("--since", default=None, help="Only findings first seen within this window (e.g. 30d, 90d).")
@click.option("--until", default=None, help="Only findings first seen before this ISO-8601 timestamp.")
def findings(
    fmt: str,
    output: str,
    severity: str | None,
    scanner: str | None,
    status: str | None,
    repo_id: str | None,
    since: str | None,
    until: str | None,
) -> None:
    """Export findings to a CSV or JSONL file.

    Streams the response directly to disk — the full result set is never
    loaded into memory.  A progress indicator shows the download count using
    the X-Total-Count header returned by the server.
    """
    cfg = load_config()
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)

    params: dict[str, str] = {"format": fmt}
    if severity:
        params["severity"] = severity
    if scanner:
        params["scanner"] = scanner
    if status:
        params["status"] = status
    if repo_id:
        params["repo_id"] = repo_id

    since_iso = _parse_since_param(since)
    if since_iso:
        params["since"] = since_iso
    if until:
        params["until"] = until

    url = f"{cfg.base_url}/api/v1/exports/findings"

    try:
        total, written = _stream_to_file(client, url, params, output)
    except AegisAPIError as exc:
        click.echo(f"Export failed: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Exported {written:,} bytes to {output} ({total:,} findings).")


def _stream_to_file(
    client: AegisClient,
    url: str,
    params: dict[str, str],
    output: str,
) -> tuple[int, int]:
    """Stream the HTTP response to *output* and return (total_count, bytes_written).

    Uses httpx streaming so the response body is never fully buffered in memory.
    Shows a progress indicator once the X-Total-Count header is available.
    """
    written = 0
    total = 0

    with client._http.stream("GET", url, params=params) as resp:
        if resp.status_code >= 400:
            raise AegisAPIError(
                f"HTTP {resp.status_code} from export endpoint",
                status_code=resp.status_code,
            )

        try:
            total = int(resp.headers.get("x-total-count", "0"))
        except ValueError:
            total = 0

        out_path = Path(output)
        with out_path.open("wb") as fh:
            for chunk in resp.iter_bytes(chunk_size=65_536):
                fh.write(chunk)
                written += len(chunk)
                _print_progress(written, total)

    # Final newline after progress indicator
    click.echo("", err=True)
    return total, written


def _print_progress(written: int, total: int) -> None:
    """Print an in-place progress line to stderr."""
    kb = written / 1024
    if total > 0:
        click.echo(f"\r  Downloading… {kb:.0f} KB / {total:,} findings", nl=False, err=True)
    else:
        click.echo(f"\r  Downloading… {kb:.0f} KB", nl=False, err=True)

"""aegis sbom — export, inspect, and diff SBOMs from cached scan data.

Subcommands
-----------
export      Download a repository or container image SBOM in the requested format.
history     List historical SBOM versions for a repository.
diff        Show component-level changes between two SBOM versions.

Examples
--------
  aegis sbom export                                    # current repo, CycloneDX JSON, stdout
  aegis sbom export --repo example-org/payments-api
  aegis sbom export --image-digest sha256:abc123
  aegis sbom export --format spdx-json
  aegis sbom export --output sbom.json
  aegis sbom history --repo example-org/payments-api
  aegis sbom diff --repo example-org/payments-api --from-hash abc123 --to-hash def456
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config

VALID_FORMATS = ("cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value")


@click.group("sbom")
def sbom_group() -> None:
    """Export and inspect SBOMs from cached scan data."""


# ── export ────────────────────────────────────────────────────────────────────

@sbom_group.command("export")
@click.option(
    "--repo",
    default=None,
    help="Repository slug (org/name).  Mutually exclusive with --image-digest.",
)
@click.option(
    "--image-digest",
    "image_digest",
    default=None,
    help="Container image digest (sha256:...).  Mutually exclusive with --repo.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(list(VALID_FORMATS), case_sensitive=False),
    default="cyclonedx-json",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write SBOM to file instead of stdout.",
)
def export_cmd(
    repo: str | None,
    image_digest: str | None,
    fmt: str,
    output: Path | None,
) -> None:
    """Export a cached SBOM as CycloneDX or SPDX.

    At least one of --repo or --image-digest is required unless a default
    repository can be inferred from the config.
    """
    if repo is not None and image_digest is not None:
        click.echo(
            "Error: --repo and --image-digest are mutually exclusive.", err=True
        )
        sys.exit(1)

    cfg = load_config()
    if not cfg.api_token:
        click.echo(
            "Error: No API token found. Set AEGIS_API_TOKEN or run `aegis login`.",
            err=True,
        )
        sys.exit(1)

    if repo is None and image_digest is None:
        click.echo(
            "Error: Provide --repo <org/name> or --image-digest <sha256:...>.",
            err=True,
        )
        sys.exit(1)

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            content = client.export_sbom(
                repo=repo,
                image_digest=image_digest,
                format=fmt,
            )
        except AegisAPIError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    if output:
        output.write_text(content, encoding="utf-8")
        click.echo(f"SBOM written to {output}")
    else:
        click.echo(content, nl=False)


# ── history ───────────────────────────────────────────────────────────────────

@sbom_group.command("history")
@click.option(
    "--repo",
    required=True,
    help="Repository slug (org/name).",
)
@click.option(
    "--limit",
    default=10,
    show_default=True,
    type=int,
    help="Maximum number of historical versions to return.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def history_cmd(
    repo: str,
    limit: int,
    output_json: bool,
) -> None:
    """List historical SBOM versions for a repository.

    Each row shows the manifest set hash, creation timestamp, and the MinIO
    blob pointer so you can trace which scan produced each SBOM.
    """
    cfg = load_config()
    if not cfg.api_token:
        click.echo(
            "Error: No API token found. Set AEGIS_API_TOKEN or run `aegis login`.",
            err=True,
        )
        sys.exit(1)

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            versions = client.list_sbom_history(repo)
        except AegisAPIError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    # Apply limit client-side so the CLI matches the --limit flag even if the
    # backend default differs.
    versions = versions[:limit]

    if output_json:
        click.echo(json.dumps(versions, indent=2))
        return

    if not versions:
        click.echo(f"No SBOM history found for {repo}.")
        return

    # Simple tabular output — intentionally avoids the Rich dependency in the
    # hot-path so the command remains fast when Rich is unavailable.
    header = f"{'HASH':<48}  {'CREATED_AT':<28}  TOOL_VERSION"
    click.echo(header)
    click.echo("-" * len(header))
    for v in versions:
        hash_val = v.get("manifest_set_hash", "")[:48]
        created = v.get("created_at", "")[:28]
        tool = v.get("tool_version", "")
        click.echo(f"{hash_val:<48}  {created:<28}  {tool}")


# ── diff ──────────────────────────────────────────────────────────────────────

@sbom_group.command("diff")
@click.option("--repo", required=True, help="Repository slug (org/name).")
@click.option("--from-hash", "from_hash", required=True, help="Source manifest_set_hash.")
@click.option("--to-hash", "to_hash", required=True, help="Target manifest_set_hash.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "markdown"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
def diff_cmd(
    repo: str,
    from_hash: str,
    to_hash: str,
    fmt: str,
) -> None:
    """Show SBOM component diff between two manifest versions.

    Compares the dependency tree at from_hash versus to_hash and prints
    which packages were added, removed, had their version bumped, or stayed
    the same.
    """
    cfg = load_config()
    if not cfg.api_token:
        click.echo(
            "Error: No API token found. Set AEGIS_API_TOKEN or run `aegis login`.",
            err=True,
        )
        sys.exit(1)

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            result = client.diff_sbom(
                repo_id=repo,
                from_hash=from_hash,
                to_hash=to_hash,
            )
        except AegisAPIError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    if fmt == "json":
        click.echo(json.dumps(result, indent=2))
    elif fmt == "markdown":
        click.echo(_format_sbom_diff_markdown(result, repo, from_hash, to_hash))
    else:
        click.echo(_format_sbom_diff_text(result, repo, from_hash, to_hash))


def _format_sbom_diff_text(result: dict, repo: str, from_hash: str, to_hash: str) -> str:
    added = result.get("added", [])
    removed = result.get("removed", [])
    version_changed = result.get("version_changed", [])
    unchanged = result.get("unchanged_count", 0)

    # Truncate hashes for readability
    fh = from_hash[:12]
    th = to_hash[:12]

    lines: list[str] = [f"SBOM diff: {repo} @ {fh}..{th}"]

    n_added = len(added)
    lines.append(f"  Added:           {n_added} component{'s' if n_added != 1 else ''}")
    for c in added:
        ver = f"@{c['version']}" if c.get("version") else ""
        lines.append(f"    + {c.get('name', '?')}{ver}")

    n_removed = len(removed)
    lines.append(f"  Removed:         {n_removed} component{'s' if n_removed != 1 else ''}")
    for c in removed:
        ver = f"@{c['version']}" if c.get("version") else ""
        lines.append(f"    - {c.get('name', '?')}{ver}")

    n_changed = len(version_changed)
    lines.append(f"  Version changed: {n_changed} component{'s' if n_changed != 1 else ''}")
    for c in version_changed:
        lines.append(
            f"    ~ {c.get('name', '?')}  {c.get('from_version', '?')} -> {c.get('to_version', '?')}"
        )

    lines.append(f"  Unchanged:       {unchanged} component{'s' if unchanged != 1 else ''}")
    return "\n".join(lines)


def _format_sbom_diff_markdown(result: dict, repo: str, from_hash: str, to_hash: str) -> str:
    added = result.get("added", [])
    removed = result.get("removed", [])
    version_changed = result.get("version_changed", [])
    unchanged = result.get("unchanged_count", 0)

    fh = from_hash[:12]
    th = to_hash[:12]

    lines: list[str] = [
        f"## SBOM diff: `{repo}` @ `{fh}..{th}`",
        "",
        f"### Added ({len(added)})",
    ]
    if added:
        for c in added:
            ver = f"@{c['version']}" if c.get("version") else ""
            lines.append(f"- `{c.get('name', '?')}{ver}`")
    else:
        lines.append("_None_")

    lines += ["", f"### Removed ({len(removed)})"]
    if removed:
        for c in removed:
            ver = f"@{c['version']}" if c.get("version") else ""
            lines.append(f"- `{c.get('name', '?')}{ver}`")
    else:
        lines.append("_None_")

    lines += ["", f"### Version changed ({len(version_changed)})"]
    if version_changed:
        for c in version_changed:
            lines.append(
                f"- `{c.get('name', '?')}`: `{c.get('from_version', '?')}` → `{c.get('to_version', '?')}`"
            )
    else:
        lines.append("_None_")

    lines += ["", f"### Unchanged: {unchanged}"]
    return "\n".join(lines)

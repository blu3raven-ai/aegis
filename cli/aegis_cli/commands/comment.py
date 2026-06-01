"""aegis comment — generate a PR comment from scan findings.

Reads findings either from the live backend (via --scan-id / latest scan) or
from a pre-existing JSON file (--from-json), then renders a platform-specific
Markdown comment ready to paste into a GitHub / GitLab / Bitbucket PR.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config
from aegis_cli.comment_formatters import (
    format_github_comment,
    format_gitlab_comment,
    format_bitbucket_comment,
)

_FORMATTERS = {
    "github": format_github_comment,
    "gitlab": format_gitlab_comment,
    "bitbucket": format_bitbucket_comment,
}


@click.command("comment")
@click.option(
    "--scan-id",
    default=None,
    help="Use findings from a specific scan run.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["github", "gitlab", "bitbucket"]),
    default="github",
    show_default=True,
    help="Target platform Markdown dialect.",
)
@click.option(
    "--max-findings",
    default=10,
    show_default=True,
    help="Maximum number of critical/high findings to include.",
)
@click.option(
    "--include-chains",
    is_flag=True,
    default=False,
    help="Include affected attack chains section.",
)
@click.option(
    "--include-decision",
    is_flag=True,
    default=False,
    help="Include go/no-go decision summary.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write comment to file instead of stdout.",
)
@click.option(
    "--from-json",
    "from_json",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Load findings from a local JSON file (output of `aegis findings --json`).",
)
@click.option(
    "--org",
    default=None,
    help="Organisation name (overrides AEGIS_DEFAULT_ORG).",
)
@click.option(
    "--repo",
    default=None,
    help="Scope to a single repository (org/name).",
)
@click.option(
    "--severity",
    default=None,
    help="Comma-separated severity filter applied before rendering: critical,high,medium,low.",
)
def comment_cmd(
    scan_id: str | None,
    fmt: str,
    max_findings: int,
    include_chains: bool,
    include_decision: bool,
    output: Path | None,
    from_json: Path | None,
    org: str | None,
    repo: str | None,
    severity: str | None,
) -> None:
    """Generate a formatted PR comment from Aegis scan findings.

    By default reads the latest scan for the configured organisation and
    writes GitHub-flavoured Markdown to stdout.  Use --from-json to skip
    the backend call and work from a saved findings JSON.

    Examples:

    \b
      aegis comment
      aegis comment --format gitlab --include-chains --include-decision
      aegis comment --from-json findings.json --output comment.md
      aegis comment --scan-id scan-abc --max-findings 5
    """
    cfg = load_config()
    base_url = cfg.base_url or "https://aegis.example.org"

    severities = [s.strip().lower() for s in severity.split(",")] if severity else None

    # --- Source: local JSON file (no auth required) ---
    if from_json is not None:
        findings = _load_findings_json(from_json)
    else:
        # --- Source: live backend ---
        if not cfg.api_token:
            click.echo(
                "Error: No API token found. Set AEGIS_API_TOKEN or run `aegis login`.",
                err=True,
            )
            sys.exit(1)

        resolved_org = org or cfg.default_org or ""
        if not resolved_org:
            click.echo(
                "Error: No org specified. Pass --org or set AEGIS_DEFAULT_ORG.",
                err=True,
            )
            sys.exit(1)

        with AegisClient(base_url, cfg.api_token) as client:
            try:
                findings = client.iter_all_findings(
                    org=resolved_org,
                    severity=severities,
                )
            except AegisAPIError as exc:
                click.echo(f"Error: {exc}", err=True)
                sys.exit(1)

        # The aggregated endpoint has no repo-only filter; keep the precise
        # client-side filter so --repo behaves the same as before the migration.
        if repo:
            findings = [
                f for f in findings if repo in (f.get("repo") or "")
            ]

    # Apply severity filter when loading from file (client applies it live)
    if from_json and severities:
        findings = [
            f for f in findings
            if _extract_severity_local(f) in severities
        ]

    if repo and from_json:
        findings = [
            f for f in findings
            if repo in (
                (f.get("repository") or {}).get("full_name", "")
                or f.get("repo", "")
            )
        ]

    total = len(findings)

    # Sort by risk score and cap for display
    from aegis_cli.report_formatters import _risk_score  # noqa: PLC0415
    findings_sorted = sorted(findings, key=_risk_score, reverse=True)
    display_findings = findings_sorted[:max_findings]

    payload: dict = {
        "findings": display_findings,
        "total_findings": total,
        "base_url": base_url,
        "scan_id": scan_id or "",
    }

    if include_chains:
        # Chains data is not surfaced via the current findings endpoint;
        # attach any chain context embedded in the findings themselves.
        payload["chains"] = _extract_chains_from_findings(findings)

    if include_decision:
        payload["decision"] = _derive_decision(findings)

    formatter = _FORMATTERS[fmt]
    text = formatter(payload)

    if output:
        output.write_text(text, encoding="utf-8")
        click.echo(f"Comment written to {output}")
    else:
        click.echo(text)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_findings_json(path: Path) -> list[dict]:
    """Parse findings from a JSON file produced by `aegis findings --json`."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        click.echo(f"Error reading {path}: {exc}", err=True)
        sys.exit(1)

    if isinstance(raw, list):
        return raw
    # Accept {"findings": [...]} envelope too
    if isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        return raw["findings"]

    click.echo(
        f"Error: {path} must contain a JSON array or {{\"findings\": [...]}} object.",
        err=True,
    )
    sys.exit(1)


def _extract_severity_local(finding: dict) -> str:
    """Pull severity for client-side filtering when working from a JSON file."""
    sec = finding.get("security_advisory") or {}
    sev = (
        sec.get("severity")
        or finding.get("severity")
        or (finding.get("rule") or {}).get("severity")
        or "unknown"
    )
    return str(sev).lower()


def _extract_chains_from_findings(findings: list[dict]) -> list[dict]:
    """Collect unique chain references embedded in findings, if any."""
    seen: set[str] = set()
    chains: list[dict] = []
    for f in findings:
        ch = f.get("chain") or f.get("attack_chain")
        if ch and isinstance(ch, dict):
            ch_id = ch.get("id") or ""
            if ch_id not in seen:
                seen.add(ch_id)
                chains.append(ch)
    return chains


def _derive_decision(findings: list[dict]) -> dict:
    """Local go/no-go heuristic — block if any critical or high finding exists."""
    blockers = [
        f for f in findings
        if _extract_severity_local(f) in ("critical", "high")
    ]
    if blockers:
        return {
            "decision": "block",
            "rationale": (
                f"{len(blockers)} critical/high finding(s) require remediation "
                "before deploy."
            ),
        }
    return {
        "decision": "allow",
        "rationale": "No critical or high severity findings.",
    }

"""aegis init — one-command project onboarding.

Creates `.aegis.yml`, a sample `.aegis/policy.yml`, and patches `.gitignore`
so teams can start scanning with minimal configuration.

Non-interactive usage (suitable for CI bootstrapping):

  aegis init --backend-url https://aegis.example.org \\
             --api-token "$AEGIS_TOKEN" \\
             --org example-org \\
             --scanners deps,sast \\
             --severity-gate critical \\
             --yes
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import httpx

from aegis_cli.config import load_config
from aegis_cli.init_templates import (
    generate_policy,
    generate_project_config,
    patch_gitignore,
)

_DEFAULT_SCANNERS = ["dependencies", "sast", "secrets", "container"]
_SCANNER_ALIASES: dict[str, str] = {
    "deps": "dependencies",
    "dep": "dependencies",
    "dependencies": "dependencies",
    "sast": "sast",
    "code": "sast",
    "secrets": "secrets",
    "secret": "secrets",
    "container": "container",
    "containers": "container",
    "image": "container",
}


def _parse_scanners(raw: str) -> list[str]:
    """Normalise a comma-separated scanner string to canonical names."""
    result: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        canonical = _SCANNER_ALIASES.get(part.strip().lower())
        if canonical and canonical not in seen:
            result.append(canonical)
            seen.add(canonical)
    return result or _DEFAULT_SCANNERS


def _validate_connection(backend_url: str, api_token: str) -> tuple[bool, str]:
    """Perform a lightweight health/ping check against the backend.

    A 200-series response is treated as success.  Any other outcome returns
    False with a descriptive reason so the caller can warn without aborting.
    """
    try:
        headers: dict[str, str] = {}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        url = backend_url.rstrip("/") + "/health"
        resp = httpx.get(url, headers=headers, timeout=8.0, follow_redirects=True)
        if resp.is_success:
            return True, f"{resp.status_code} OK"
        return False, f"HTTP {resp.status_code}"
    except httpx.ConnectError:
        return False, "connection refused"
    except httpx.TimeoutException:
        return False, "request timed out"
    except Exception as exc:  # pragma: no cover
        return False, str(exc)


@click.command("init")
@click.option(
    "--backend-url",
    default=None,
    help="Aegis backend URL (e.g. https://aegis.example.org).",
)
@click.option(
    "--api-token",
    default=None,
    help="API token for connectivity check (never written to .aegis.yml).",
)
@click.option(
    "--org",
    default=None,
    help="Default organisation slug.",
)
@click.option(
    "--scanners",
    default=None,
    help="Comma-separated scanner mix: dependencies,sast,secrets,container.",
)
@click.option(
    "--severity-gate",
    "severity_gate",
    default=None,
    type=click.Choice(["critical", "high", "medium", "none"], case_sensitive=False),
    help="Severity level at which CI should fail.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip all interactive prompts, accept defaults.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing .aegis.yml without confirmation.",
)
@click.option(
    "--project-dir",
    "project_dir",
    default=".",
    type=click.Path(file_okay=False, path_type=Path),
    hidden=True,
    help="Project root (defaults to cwd; exposed for testing).",
)
@click.option(
    "--skip-validation",
    "skip_validation",
    is_flag=True,
    default=False,
    hidden=True,
    help="Skip backend connectivity check (for offline/testing use).",
)
def init_cmd(
    backend_url: str | None,
    api_token: str | None,
    org: str | None,
    scanners: str | None,
    severity_gate: str | None,
    yes: bool,
    force: bool,
    project_dir: Path,
    skip_validation: bool,
) -> None:
    """Initialize a project for Aegis scanning.

    Creates .aegis.yml, a sample .aegis/policy.yml, and patches .gitignore.

    \b
    Examples:
      aegis init
      aegis init --backend-url https://aegis.example.org --yes
      aegis init --scanners dependencies,sast --severity-gate critical --yes
    """
    project_dir = project_dir.resolve()
    project_name = project_dir.name

    click.echo(f"Initializing Aegis for {project_name}\n")

    # -----------------------------------------------------------------
    # Resolve configuration — flags > env/config > interactive prompts
    # -----------------------------------------------------------------
    cfg = load_config()

    resolved_url = backend_url or cfg.base_url
    resolved_org = org or cfg.default_org or ""
    resolved_token = api_token or cfg.api_token or ""

    if not yes:
        resolved_url = click.prompt(
            "Aegis backend URL", default=resolved_url or "https://aegis.example.org"
        )
        resolved_token = click.prompt(
            "API token (paste, hidden; leave blank to skip)", hide_input=True, default=""
        )
        resolved_org = click.prompt(
            "Default org slug",
            default=resolved_org or "example-org",
        )
        scanners_input = click.prompt(
            "Scanner mix (comma-separated)",
            default=scanners or "dependencies,sast,secrets,container",
        )
        severity_gate = click.prompt(
            "Severity gate for CI",
            default=severity_gate or "critical",
            type=click.Choice(["critical", "high", "medium", "none"], case_sensitive=False),
        )
    else:
        scanners_input = scanners or "dependencies,sast,secrets,container"
        severity_gate = severity_gate or "critical"

    resolved_scanners = _parse_scanners(scanners_input)

    # -----------------------------------------------------------------
    # Check for existing .aegis.yml
    # -----------------------------------------------------------------
    project_config_path = project_dir / ".aegis.yml"
    if project_config_path.exists() and not force:
        if yes:
            click.echo(
                f"  .aegis.yml already exists at {project_config_path}. "
                "Pass --force to overwrite.",
                err=True,
            )
            sys.exit(1)
        if not click.confirm(f".aegis.yml already exists. Overwrite?"):
            click.echo("Aborted.")
            return

    # -----------------------------------------------------------------
    # Write .aegis.yml
    # -----------------------------------------------------------------
    config_content = generate_project_config(
        backend_url=resolved_url,
        default_org=resolved_org or "example-org",
        scanners=resolved_scanners,
        severity_gate=severity_gate.lower(),
    )
    project_config_path.write_text(config_content, encoding="utf-8")
    click.echo(f"  Created {project_config_path.relative_to(project_dir)}")

    # -----------------------------------------------------------------
    # Write .aegis/policy.yml
    # -----------------------------------------------------------------
    policy_dir = project_dir / ".aegis"
    policy_dir.mkdir(exist_ok=True)
    policy_path = policy_dir / "policy.yml"
    if not policy_path.exists() or force:
        policy_path.write_text(generate_policy(), encoding="utf-8")
        click.echo(f"  Created .aegis/policy.yml (example block-on-critical policy)")
    else:
        click.echo(f"  Skipped .aegis/policy.yml (already exists)")

    # -----------------------------------------------------------------
    # Patch .gitignore
    # -----------------------------------------------------------------
    gitignore_path = project_dir / ".gitignore"
    added = patch_gitignore(gitignore_path)
    if added:
        click.echo(f"  Updated .gitignore (added .aegis/cache/)")
    else:
        click.echo(f"  .gitignore already contains Aegis entries (skipped)")

    # -----------------------------------------------------------------
    # Validate connectivity
    # -----------------------------------------------------------------
    if not skip_validation:
        click.echo()
        ok, reason = _validate_connection(resolved_url, resolved_token)
        if ok:
            click.echo(f"  Validated connection to {resolved_url} ({reason})")
        else:
            click.echo(
                f"  Could not reach {resolved_url}: {reason}. "
                "Config written — check connectivity before scanning.",
                err=True,
            )

    # -----------------------------------------------------------------
    # Next steps
    # -----------------------------------------------------------------
    click.echo("\nNext steps:")
    click.echo("  1. Run a smoke scan:  aegis scan")
    click.echo("  2. View findings:     aegis findings")
    click.echo("  3. Add to CI: see examples/ci/ in the Aegis repo")

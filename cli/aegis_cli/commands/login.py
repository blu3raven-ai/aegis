"""Interactive credential setup. Writes ~/.aegis/config.toml."""
from __future__ import annotations

import os
from pathlib import Path

import click

CONFIG_PATH = Path.home() / ".aegis" / "config.toml"


@click.command("login")
@click.option("--base-url", help="Aegis backend URL (e.g., https://aegis.example.org)")
@click.option("--api-token", help="Aegis API token")
@click.option("--default-org", help="Default org slug")
@click.option("--force", is_flag=True, help="Overwrite existing config without prompting")
def login(
    base_url: str | None,
    api_token: str | None,
    default_org: str | None,
    force: bool,
) -> None:
    """Set up Aegis CLI credentials interactively or via flags."""
    if CONFIG_PATH.exists() and not force:
        if not click.confirm(f"Config exists at {CONFIG_PATH}. Overwrite?"):
            click.echo("Aborted.")
            return

    if not base_url:
        base_url = click.prompt("Aegis backend URL", default="https://aegis.example.org")
    if not api_token:
        click.echo("  Tip: create an API token at Settings → API keys (/settings/api-keys)")
        api_token = click.prompt("API token", hide_input=True)
    if not default_org:
        default_org = click.prompt("Default org slug (optional)", default="", show_default=False)

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Best-effort restrictive perms on the directory (config is per-user)
    try:
        os.chmod(CONFIG_PATH.parent, 0o700)
    except OSError:
        pass

    content = f"""base_url = "{base_url}"
api_token = "{api_token}"
default_org = "{default_org}"
"""
    CONFIG_PATH.write_text(content)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass

    click.echo(f"Saved to {CONFIG_PATH}")

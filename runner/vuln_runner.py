#!/usr/bin/env python3
# runner/vuln_runner.py
"""CLI entry point for the vulnerability scanner runner agent."""
from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

import click
import httpx

from runner.agent import CONFIG_PATH, RunnerAgent, load_config, save_config


@click.group()
def cli() -> None:
    """Vulnerability Scanner Runner Agent"""
    pass


@cli.command()
@click.option("--url", required=True, help="Portal URL (e.g., https://portal.example.com)")
@click.option("--token", required=True, help="Registration token from the portal")
@click.option("--name", default="", help="Runner name (defaults to hostname)")
@click.option("--insecure", is_flag=True, help="Allow non-HTTPS connections (dev only)")
def configure(url: str, token: str, name: str, insecure: bool) -> None:
    """Register this runner with the portal."""
    url = url.rstrip("/")

    if not insecure and not url.startswith("https://"):
        click.echo("Error: Portal URL must use HTTPS. Use --insecure for local development.", err=True)
        sys.exit(1)

    runner_name = name or platform.node() or "runner"

    click.echo(f"Registering runner '{runner_name}' with {url}...")

    try:
        with httpx.Client(timeout=15.0, verify=not insecure) as client:
            resp = client.post(
                f"{url}/runner/api/register",
                json={
                    "token": token,
                    "name": runner_name,
                    "os": platform.system().lower(),
                    "arch": platform.machine(),
                },
            )

        if resp.status_code != 200:
            error = resp.json().get("error", resp.text)
            click.echo(f"Registration failed: {error}", err=True)
            sys.exit(1)

        data = resp.json()
        config = {
            "portalUrl": url,
            "runnerId": data["runnerId"],
            "authToken": data["authToken"],
            "name": runner_name,
        }
        save_config(config)

        click.echo(f"Runner registered: {data['runnerId']}")
        click.echo(f"Status: {data['status']}")
        click.echo(f"Config saved to: {CONFIG_PATH}")
        click.echo("")
        click.echo("Next steps:")
        click.echo("  1. Ask an admin to approve this runner in Settings > Runners")
        click.echo("  2. Then run: ./vuln-runner start")

    except httpx.ConnectError:
        click.echo(f"Error: Could not connect to {url}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--insecure", is_flag=True, help="Allow non-HTTPS connections (dev only)")
def start(insecure: bool) -> None:
    """Start the runner agent."""
    try:
        config = load_config()
    except FileNotFoundError as e:
        click.echo(str(e), err=True)
        sys.exit(1)

    if not insecure and not config["portalUrl"].startswith("https://"):
        click.echo("Error: Portal URL must use HTTPS. Use --insecure for local development.", err=True)
        sys.exit(1)

    agent = RunnerAgent(config)

    click.echo(f"Runner: {config.get('name', 'runner')}")
    click.echo(f"Portal: {config['portalUrl']}")
    click.echo("Press Ctrl+C to stop")
    click.echo("")

    try:
        agent.start()
    except KeyboardInterrupt:
        click.echo("\nStopping runner...")
        agent.stop()


if __name__ == "__main__":
    cli()

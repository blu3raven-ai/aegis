"""aegis decide — go/no-go decision gate for CI/CD pipelines.

When the backend's /api/v1/decisions/go-no-go endpoint is not yet available,
the command falls back to a local heuristic: block if any open findings exist
at the requested severity levels, allow otherwise.  The output indicates which
path was taken so pipelines can distinguish backend-authorised from local decisions.
"""

from __future__ import annotations

import sys

import click

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config
from aegis_cli.output import console, err_console, format_decision


@click.command("decide")
@click.option("--org", default=None, help="Organisation name (overrides AEGIS_DEFAULT_ORG).")
@click.option("--repo", default=None, help="Repository name (org/name) to scope decision to.")
@click.option("--service", "service_id", default=None, help="Service identifier for Argus scoring.")
@click.option(
    "--block-on",
    default="critical",
    show_default=True,
    help="Comma-separated severity levels that trigger a block (e.g. critical,high).",
)
@click.option(
    "--exit-code",
    "use_exit_code",
    is_flag=True,
    default=False,
    help="Exit with code 1 on block, 0 on allow.  Designed for CI gate usage.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output result as JSON.",
)
def decide_cmd(
    org: str | None,
    repo: str | None,
    service_id: str | None,
    block_on: str,
    use_exit_code: bool,
    output_json: bool,
) -> None:
    """Return a Go/No-Go deployment decision for the current branch.

    Uses the backend decision endpoint when available; falls back to a local
    heuristic (inspect open findings) when the endpoint returns 404.

    Exit codes when --exit-code is set:
      0  allow / warn
      1  block
    """
    cfg = load_config()
    resolved_org = org or cfg.default_org
    if not resolved_org:
        err_console.print(
            "[bold red]Error:[/bold red] No org specified. "
            "Pass --org or set AEGIS_DEFAULT_ORG."
        )
        sys.exit(1)
    if not cfg.api_token:
        err_console.print(
            "[bold red]Error:[/bold red] No API token. Set AEGIS_API_TOKEN."
        )
        sys.exit(1)

    block_levels = [s.strip() for s in block_on.split(",") if s.strip()]
    resolved_repo = repo or resolved_org  # fall back to org scope

    with AegisClient(cfg.base_url, cfg.api_token) as client:
        try:
            decision = client.get_decision(
                org=resolved_org,
                repo=resolved_repo,
                service_id=service_id,
                block_on=block_levels,
            )
        except AegisAPIError as exc:
            err_console.print(f"[bold red]Decision error:[/bold red] {exc}")
            sys.exit(1)

    if output_json:
        import json as _json
        console.print_json(_json.dumps(decision, default=str))
    else:
        console.print(
            format_decision(decision, exit_code_mode=use_exit_code), end=""
        )

    if use_exit_code and decision.get("decision") == "block":
        sys.exit(1)

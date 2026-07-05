"""aegis mcp — start the Aegis MCP server for AI coding assistant integration."""

from __future__ import annotations

import asyncio

import click


@click.command(name="mcp")
@click.option(
    "--http",
    type=int,
    default=None,
    metavar="PORT",
    help="Run on HTTP transport at the given port instead of stdio.",
)
def mcp_serve(http: int | None) -> None:
    """Start the Aegis MCP server.

    By default runs on stdio, which is the transport expected by Claude Code,
    Cursor, Windsurf, and Claude Desktop.  Pass --http <port> for HTTP
    transport (not yet implemented).

    Example Claude Code MCP config (~/.claude/mcp_servers.json):\n
    \b
      {
        "mcpServers": {
          "aegis": { "command": "aegis", "args": ["mcp"] }
        }
      }
    """
    if http is not None:
        click.echo(
            "HTTP transport is not yet implemented. Use stdio (omit --http).",
            err=True,
        )
        raise SystemExit(1)

    from aegis_cli.mcp.server import run_stdio

    asyncio.run(run_stdio())

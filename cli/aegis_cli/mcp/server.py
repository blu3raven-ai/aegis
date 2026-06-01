"""Aegis MCP server.

Exposes scan tools and findings resources to AI coding assistants
(Claude Code, Cursor, Windsurf, Claude Desktop) via the Model Context Protocol.

Each tool delegates to AegisClient so the same auth/config path used by the CLI
applies here too.  Resources map aegis:// URIs to live backend data.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, ResourceTemplate, TextContent, Tool

from aegis_cli.client import AegisClient, AegisAPIError
from aegis_cli.config import load_config


def _build_server() -> tuple[Server, AegisClient, Any]:
    """Construct the MCP Server, AegisClient, and config.

    Separated from run_stdio so tests can call it without starting IO.
    """
    cfg = load_config()
    client = AegisClient(base_url=cfg.base_url, api_token=cfg.api_token)
    server = Server("aegis")
    return server, client, cfg


def _register_handlers(server: Server, client: AegisClient, cfg: Any) -> None:
    """Register all tool and resource handlers on *server*.

    Extracted so tests can call it independently.
    """

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="scan_current_workspace",
                description=(
                    "Trigger an Aegis vulnerability scan on the current workspace. "
                    "Returns scan_id and queued status."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scanner_type": {
                            "type": "string",
                            "default": "dependencies",
                            "description": (
                                "Scanner to run. One of: dependencies, "
                                "code_scanning, secrets, containers."
                            ),
                        },
                        "repo": {
                            "type": "string",
                            "description": "Optional repo hint (org/name).",
                        },
                    },
                    "required": [],
                },
            ),
            Tool(
                name="get_findings",
                description=(
                    "List active vulnerability findings for a repo or org. "
                    "Returns a JSON array of finding objects."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Filter by repository (org/name).",
                        },
                        "severity": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Severity filter: critical, high, medium, low.",
                        },
                        "scanner": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Scanner filter: dependencies, code_scanning, "
                                "secrets, containers."
                            ),
                        },
                    },
                    "required": [],
                },
            ),
            Tool(
                name="explain_finding",
                description=(
                    "Get an AI-rendered explanation of a finding including "
                    "markdown description and fix suggestions."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "The finding ID to explain.",
                        },
                    },
                    "required": ["finding_id"],
                },
            ),
            Tool(
                name="lookup_cve",
                description=(
                    "Look up CVE details including EPSS score and exploit availability."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": "CVE identifier, e.g. CVE-2024-12345.",
                        },
                    },
                    "required": ["cve_id"],
                },
            ),
            Tool(
                name="check_dependency",
                description=(
                    "Check whether a specific package version is known to be vulnerable. "
                    "Returns vulnerability status and relevant advisories."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "package_name": {
                            "type": "string",
                            "description": "Package name, e.g. lodash.",
                        },
                        "version": {
                            "type": "string",
                            "description": "Package version, e.g. 4.17.20.",
                        },
                    },
                    "required": ["package_name", "version"],
                },
            ),
            Tool(
                name="get_decision",
                description=(
                    "Get a go/no-go deployment decision for a service or PR. "
                    "Returns decision (allow/block), blockers, and rationale."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "service_id": {
                            "type": "string",
                            "description": "Service identifier to assess.",
                        },
                        "repo": {
                            "type": "string",
                            "description": "Repository (org/name) to assess.",
                        },
                        "block_on": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Severity levels that trigger a block decision. "
                                "Defaults to [critical]."
                            ),
                        },
                    },
                    "required": [],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        try:
            result = await _dispatch_tool(name, arguments, client, cfg)
        except AegisAPIError as exc:
            return [TextContent(type="text", text=f"Aegis API error: {exc}")]
        except ValueError as exc:
            return [TextContent(type="text", text=str(exc))]
        return [TextContent(type="text", text=result)]

    @server.list_resource_templates()
    async def list_resource_templates() -> list[ResourceTemplate]:
        return [
            ResourceTemplate(
                uriTemplate="aegis://findings/{repo}",
                name="Findings",
                description="Active findings for a repository. Replace {repo} with org/name.",
                mimeType="application/json",
            ),
            ResourceTemplate(
                uriTemplate="aegis://sbom/{repo}",
                name="SBOM",
                description="Current SBOM for a repository. Replace {repo} with org/name.",
                mimeType="application/json",
            ),
            ResourceTemplate(
                uriTemplate="aegis://chains/{chain_id}",
                name="Chain",
                description="Attack chain detail by ID.",
                mimeType="application/json",
            ),
        ]

    @server.list_resources()
    async def list_resources() -> list[Resource]:
        # Static examples shown before a repo is specified.
        return [
            Resource(
                uri="aegis://findings/example-org/api-service",
                name="Findings — example-org/api-service",
                description="Active findings for example-org/api-service.",
                mimeType="application/json",
            ),
        ]

    @server.read_resource()
    async def read_resource(uri: str) -> str:
        return await _dispatch_resource(str(uri), client, cfg)


async def _dispatch_tool(
    name: str,
    arguments: dict[str, Any],
    client: AegisClient,
    cfg: Any,
) -> str:
    """Route a tool call to the matching AegisClient method.

    Returns a JSON string (or human-readable text) to send back as TextContent.
    """
    org = cfg.default_org or "unknown-org"

    if name == "scan_current_workspace":
        result = await asyncio.to_thread(
            client.trigger_scan,
            org=org,
            scanner_type=arguments.get("scanner_type", "dependencies"),
            repo=arguments.get("repo"),
        )
        return json.dumps(result, indent=2)

    if name == "get_findings":
        findings = await asyncio.to_thread(
            client.get_findings,
            org=org,
            repo=arguments.get("repo"),
            severity=arguments.get("severity"),
            scanner=arguments.get("scanner"),
        )
        return json.dumps(findings, indent=2)

    if name == "explain_finding":
        finding_id = arguments["finding_id"]
        explanation = await asyncio.to_thread(
            client.get_explanation,
            finding_id=finding_id,
        )
        return json.dumps(explanation, indent=2)

    if name == "lookup_cve":
        cve_id = arguments["cve_id"]
        info = await asyncio.to_thread(client.lookup_cve, cve_id=cve_id)
        return json.dumps(info, indent=2)

    if name == "check_dependency":
        result = await asyncio.to_thread(
            client.check_dependency,
            package_name=arguments["package_name"],
            version=arguments["version"],
        )
        return json.dumps(result, indent=2)

    if name == "get_decision":
        repo = arguments.get("repo") or org
        result = await asyncio.to_thread(
            client.get_decision,
            org=org,
            repo=repo,
            service_id=arguments.get("service_id"),
            block_on=arguments.get("block_on"),
        )
        return json.dumps(result, indent=2)

    raise ValueError(f"Unknown tool: {name}")


async def _dispatch_resource(uri: str, client: AegisClient, cfg: Any) -> str:
    """Fetch data for an aegis:// resource URI and return JSON string."""
    org = cfg.default_org or "unknown-org"

    if uri.startswith("aegis://findings/"):
        repo = uri.removeprefix("aegis://findings/")
        findings = await asyncio.to_thread(
            client.get_findings,
            org=org,
            repo=repo,
        )
        return json.dumps(findings, indent=2)

    if uri.startswith("aegis://sbom/"):
        repo = uri.removeprefix("aegis://sbom/")
        sbom = await asyncio.to_thread(client.get_sbom, repo=repo, org=org)
        return json.dumps(sbom, indent=2)

    if uri.startswith("aegis://chains/"):
        chain_id = uri.removeprefix("aegis://chains/")
        chain = await asyncio.to_thread(client.get_chain, chain_id=chain_id, org=org)
        return json.dumps(chain, indent=2)

    raise ValueError(f"Unknown resource URI: {uri}")


async def run_stdio() -> None:
    """Start the MCP server on stdio. Called by `aegis mcp`."""
    server, client, cfg = _build_server()
    _register_handlers(server, client, cfg)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )

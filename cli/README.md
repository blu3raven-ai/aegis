# Aegis CLI

Command-line interface for Aegis — trigger vulnerability scans, query findings,
and gate CI/CD pipelines from your terminal or scripts.

## Installation

```sh
pip install aegis-cli
```

## Configuration

Configuration is loaded from environment variables first, then `~/.aegis/config.toml`.

| Variable          | Description                                   | Default                       |
|-------------------|-----------------------------------------------|-------------------------------|
| `AEGIS_BASE_URL`  | Backend URL                                   | `https://aegis.example.org`   |
| `AEGIS_API_TOKEN` | API authentication token                      | (from `~/.aegis/credentials`) |
| `AEGIS_DEFAULT_ORG` | Default organisation name                   | (none)                        |

## Commands

```
aegis login      Interactive credential setup
aegis scan       Trigger a vulnerability scan
aegis status     Check scan run status
aegis decide     Get a go/no-go deployment decision
aegis findings   List open findings
aegis mcp        Start the Aegis MCP server
```

## MCP server

Aegis can run as an [MCP](https://modelcontextprotocol.io) server so AI coding
assistants (Claude Code, Cursor, Windsurf, Claude Desktop) can call scan tools
and read findings as agentic tools and resources.

Start the server on stdio (the default transport for AI agents):

```sh
aegis mcp
```

### Claude Code

Add to your MCP config (`~/.claude/mcp_servers.json` or the project-level
`.claude/mcp_servers.json`):

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis",
      "args": ["mcp"]
    }
  }
}
```

### Cursor / Windsurf / Claude Desktop

Point the assistant's MCP server config at `aegis mcp` using the same
stdio transport pattern above. Consult each tool's MCP documentation for
the exact config file location.

### Available tools

| Tool | Description |
|------|-------------|
| `scan_current_workspace` | Trigger a scan for the current org. Returns scan ID and queued status. |
| `get_findings` | List active findings. Filterable by repo, severity, and scanner type. |
| `explain_finding` | Get an AI explanation and fix suggestions for a finding. |
| `lookup_cve` | Look up CVE details: EPSS score and exploit availability. |
| `check_dependency` | Check whether a package version is vulnerable. |
| `get_decision` | Get a go/no-go deployment decision with blockers and rationale. |

### Available resources

| URI | Description |
|-----|-------------|
| `aegis://findings/{repo}` | Live findings list for a repository. |
| `aegis://sbom/{repo}` | Current SBOM for a repository. |
| `aegis://chains/{chain_id}` | Attack chain detail by ID. |

### HTTP transport

HTTP transport is reserved for a future release. Today only stdio is supported:

```sh
# Not yet implemented — use stdio instead
aegis mcp --http 8080
```

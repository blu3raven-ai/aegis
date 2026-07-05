# Aegis Security Scanner

Surface vulnerability findings from a self-hosted [Aegis](https://github.com/blu3raven-ai/aegis) backend directly in your editor. Findings appear as inline diagnostics, in the Problems panel, and in a dedicated sidebar tree -- with quick-fix actions for snooze, mark-as-fixed, and attack chain inspection. A separate live view streams new findings from the backend as scans complete.

The extension is a thin wrapper around the `aegis` CLI. It does not call the backend directly: authentication, network retries, and config precedence stay in the CLI layer.

## Requirements

- **Aegis CLI** in your `PATH`, or set `aegis.cliPath` to an absolute path.
  ```
  pip install aegis-cli
  ```
  Chain visualisation, snooze, and mark-as-fixed require `aegis` CLI version 0.5 or later.
- **Aegis backend** URL and API token, obtained from your Aegis administrator.

The CLI also reads `AEGIS_BASE_URL`, `AEGIS_API_TOKEN`, and `AEGIS_DEFAULT_ORG` from the environment, so existing shell config carries over.

## Features

### Diagnostics

Findings are mapped onto VS Code's diagnostic severities:

| Aegis severity | VS Code diagnostic |
|---|---|
| Critical, High | Error |
| Medium | Warning |
| Low | Information |

The `source` column shows `aegis/<scanner> [<severity>]` so the Problems panel filter remains useful for narrowing by scanner.

### Sidebar tree views

The Aegis activity-bar icon opens two views:

- **Findings** -- the current snapshot, grouped Severity -> Scanner -> File -> Line. Severity groups appear in fixed order (Critical, High, Medium, Low). Counts are shown at every level. Clicking a leaf jumps to the offending line.
- **Live Findings** -- streams findings from the backend SSE event bus as scans complete, capped at 100 entries (FIFO). Grouped by severity. Status bar reflects connection state.

### Quick-fix actions

On any line with an Aegis diagnostic, the lightbulb menu (`Cmd+.` / `Ctrl+.`) offers:

- **Show details** -- read-only finding metadata in a side document
- **Show attack chain** -- SVG chain graph in a webview (when the finding belongs to a chain)
- **Snooze for 7 days** -- suppress the finding for one week
- **Mark as fixed** -- flag the finding as remediated on the backend

### Chain graph webview

The chain webview renders attack chains as a themed SVG using VS Code colour tokens, so dark, light, and high-contrast themes all work. The layout is computed in-process with a BFS algorithm; no external JS libraries are loaded.

### Context-menu scans

- Right-click any folder in the Explorer to run a SAST scan scoped to that directory.
- Right-click any file in the Explorer or the editor title bar to scan a single file.
- Use `Aegis: Rescan with Latest Rules` (sidebar header button) to invalidate cached findings and re-run with the current rule pack.

## Commands

| Command | Purpose |
|---|---|
| `Aegis: Scan Current Repo` | Trigger a fresh scan and wait for results |
| `Aegis: Refresh Findings` | Fetch the latest findings without triggering a new scan |
| `Aegis: Check Decision` | Show the go/no-go deployment decision for the current branch |
| `Aegis: Show Attack Chain` | Open the chain graph webview for a given chain ID |
| `Aegis: Snooze Finding for 7 Days` | Suppress the finding for one week |
| `Aegis: Mark Finding as Fixed` | Mark the finding as remediated on the backend |
| `Aegis: Show Finding Details` | Open a read-only document with full finding metadata |
| `Aegis: Scan This Folder` | Run a SAST scan scoped to a folder |
| `Aegis: Scan This File` | Run a SAST scan scoped to a single file |
| `Aegis: Rescan with Latest Rules` | Invalidate cached findings and re-run with the current rule pack |
| `Aegis: Start Live Findings` | Connect to the backend SSE stream and populate the Live Findings view |
| `Aegis: Stop Live Findings` | Disconnect from the SSE stream |
| `Aegis: Clear Live Findings` | Empty the Live Findings view |

All commands are available through the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`) and the Aegis sidebar.

## Extension Settings

| Setting | Default | Description |
|---|---|---|
| `aegis.cliPath` | `aegis` | Path to the `aegis` CLI binary. Must be in `PATH` or an absolute path. |
| `aegis.baseUrl` | _(empty)_ | Aegis backend URL, e.g. `https://aegis.example.org`. |
| `aegis.apiToken` | _(empty)_ | API token for backend authentication. |
| `aegis.org` | _(empty)_ | Default organisation slug. Overrides the `AEGIS_DEFAULT_ORG` env var. |
| `aegis.scanOnSave` | `false` | Refresh findings automatically when a file is saved. |

Settings are injected as environment variables into each CLI subprocess; they do not write to the CLI's on-disk config.

## Known Limitations

- `aegis.scanOnSave` is read at activation time. Toggling this setting requires a window reload to take effect; all other settings are read fresh per command invocation.
- VS Code has no "Critical" diagnostic tier, so Critical and High severities both render as `Error`. The original severity remains visible in the `source` column.
- The Live Findings view holds at most 100 entries; older entries are evicted FIFO. The view does not persist across window reloads.
- The extension never calls the backend directly. All operations require a working `aegis` CLI; a missing or outdated CLI will surface as a notification.

## Troubleshooting

- **"Failed to launch aegis CLI"** -- ensure `aegis` is in `PATH`, or set `aegis.cliPath` to the absolute path of the binary.
- **"aegis CLI exited with code 1"** -- verify `aegis.baseUrl` and `aegis.apiToken` are set; run `aegis findings` in a terminal to see the underlying error.
- **"aegis CLI version too old"** -- chain, snooze, and mark-as-fixed commands require `aegis` CLI 0.5 or later. Check with `aegis --version`.
- **No findings appear** -- the CLI requires `aegis.org` or `AEGIS_DEFAULT_ORG` to scope queries. Without an org, the backend cannot resolve the request.

## Release Notes

See the [CHANGELOG](./CHANGELOG.md) for the version history.

## Source and Issues

- Source: <https://github.com/blu3raven-ai/aegis/tree/main/vscode-extension>
- Issues: <https://github.com/blu3raven-ai/aegis/issues>

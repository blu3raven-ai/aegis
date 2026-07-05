# Changelog

All notable changes to the Aegis Security Scanner extension are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

### Added

- **Live Findings view** -- second sidebar tree that streams findings from the
  backend SSE event bus as scans complete. Capped at 100 entries (FIFO), grouped
  by severity. Status-bar indicator reflects connection state.
- Commands `Aegis: Start Live Findings`, `Aegis: Stop Live Findings`, and
  `Aegis: Clear Live Findings`.
- Folder- and file-scoped SAST scanning via Explorer and editor-title context
  menus (`Aegis: Scan This Folder`, `Aegis: Scan This File`).
- `Aegis: Rescan with Latest Rules` command to invalidate cached findings and
  re-run with the current rule pack.

## [0.1.0]

### Added

- Diagnostics integration: findings appear inline and in the Problems panel,
  mapped to VS Code severities with the original severity preserved in the
  `source` column.
- **Findings** sidebar tree, grouped Severity -> Scanner -> File -> Line, with
  counts at every level and click-to-jump navigation.
- Commands `Aegis: Scan Current Repo`, `Aegis: Refresh Findings`, and
  `Aegis: Check Decision`.
- Attack chain webview: themed SVG graph rendered via in-process BFS layout, no
  external JS libraries.
- Quick-fix actions on Aegis diagnostics: show details, show attack chain,
  snooze for 7 days, mark as fixed.
- Configuration: `aegis.cliPath`, `aegis.baseUrl`, `aegis.apiToken`,
  `aegis.org`, `aegis.scanOnSave`.
- CLI-only subprocess model: extension never calls the backend directly.

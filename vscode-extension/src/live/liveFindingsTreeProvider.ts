/**
 * Tree provider for the live-findings view (Aegis: Start Live Findings).
 *
 * Unlike the regular findings tree, this one is fed by an SSE stream and
 * stores only the most recent N events.  Layout is intentionally flatter
 * (Severity → leaf) so each new finding is a single noticeable line, not
 * buried under file/scanner sub-groups.
 */
import * as path from 'path'
import * as vscode from 'vscode'
import { FindingEvent } from './sseClient'

export const MAX_LIVE_ITEMS = 100

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'] as const
type SeverityKey = (typeof SEVERITY_ORDER)[number]

function severityKey(sev?: string): SeverityKey {
  const s = (sev ?? '').toLowerCase()
  return (SEVERITY_ORDER as readonly string[]).includes(s)
    ? (s as SeverityKey)
    : 'unknown'
}

function severityIcon(sev: SeverityKey): vscode.ThemeIcon {
  switch (sev) {
    case 'critical':
    case 'high':
      return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'))
    case 'medium':
      return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'))
    case 'low':
      return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'))
    default:
      return new vscode.ThemeIcon('circle-outline')
  }
}

export class LiveSeverityGroupNode extends vscode.TreeItem {
  constructor(
    public readonly severity: SeverityKey,
    public readonly count: number,
  ) {
    const label = severity.charAt(0).toUpperCase() + severity.slice(1)
    super(`${label} (${count})`, vscode.TreeItemCollapsibleState.Expanded)
    this.iconPath = severityIcon(severity)
    this.contextValue = 'aegisLiveSeverityGroup'
    this.tooltip = `${count} live ${severity} finding${count !== 1 ? 's' : ''}`
  }
}

export class LiveFindingNode extends vscode.TreeItem {
  constructor(public readonly entry: FindingEvent) {
    const title = entry.title ?? entry.finding_id ?? '(no title)'
    super(title, vscode.TreeItemCollapsibleState.None)

    const scanner = entry.scanner_type ?? 'unknown'
    const loc = entry.file_path
      ? `${path.basename(entry.file_path)}:${entry.line ?? '?'}`
      : ''
    this.description = loc ? `${scanner} - ${loc}` : scanner
    this.tooltip = buildTooltip(entry)
    this.iconPath = severityIcon(severityKey(entry.severity))
    this.contextValue = 'aegisLiveFinding'

    if (entry.file_path) {
      const line = Math.max(0, (entry.line ?? 1) - 1)
      this.command = {
        command: 'vscode.open',
        title: 'Go to live finding',
        arguments: [
          vscode.Uri.file(entry.file_path),
          { selection: new vscode.Range(line, 0, line, 0) },
        ],
      }
    }
  }
}

function buildTooltip(entry: FindingEvent): string {
  const lines = [
    `[${(entry.severity ?? 'unknown').toUpperCase()}] ${entry.title ?? entry.finding_id ?? '(no title)'}`,
    `event: ${entry.event_type}`,
  ]
  if (entry.scanner_type) lines.push(`scanner: ${entry.scanner_type}`)
  if (entry.file_path) lines.push(`file: ${entry.file_path}:${entry.line ?? '?'}`)
  if (entry.finding_id) lines.push(`id: ${entry.finding_id}`)
  return lines.join('\n')
}

export type LiveTreeItem = LiveSeverityGroupNode | LiveFindingNode

/**
 * In-memory FIFO of finding events, capped at MAX_LIVE_ITEMS.  When a new
 * event arrives for a finding we already track, the previous entry is
 * removed first so each finding occupies at most one row.
 */
export class LiveFindingsTreeProvider
  implements vscode.TreeDataProvider<LiveTreeItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<LiveTreeItem | undefined | null>()
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event

  private entries: FindingEvent[] = []

  /** Number of entries currently tracked.  Drives the status bar count. */
  size(): number {
    return this.entries.length
  }

  /** Read-only snapshot of stored entries (newest last).  For tests. */
  snapshot(): readonly FindingEvent[] {
    return this.entries
  }

  add(entry: FindingEvent): void {
    if (entry.finding_id) {
      const existingIdx = this.entries.findIndex(
        (e) => e.finding_id === entry.finding_id,
      )
      if (existingIdx !== -1) this.entries.splice(existingIdx, 1)
    }
    this.entries.push(entry)
    while (this.entries.length > MAX_LIVE_ITEMS) this.entries.shift()
    this._onDidChangeTreeData.fire(null)
  }

  clear(): void {
    this.entries = []
    this._onDidChangeTreeData.fire(null)
  }

  getTreeItem(element: LiveTreeItem): vscode.TreeItem {
    return element
  }

  getChildren(element?: LiveTreeItem): LiveTreeItem[] {
    if (!element) return this.buildSeverityGroups()
    if (element instanceof LiveSeverityGroupNode) {
      return this.buildLeavesFor(element.severity)
    }
    return []
  }

  private buildSeverityGroups(): LiveSeverityGroupNode[] {
    const counts = new Map<SeverityKey, number>()
    for (const e of this.entries) {
      const k = severityKey(e.severity)
      counts.set(k, (counts.get(k) ?? 0) + 1)
    }
    const groups: LiveSeverityGroupNode[] = []
    for (const sev of SEVERITY_ORDER) {
      const c = counts.get(sev)
      if (c && c > 0) groups.push(new LiveSeverityGroupNode(sev, c))
    }
    return groups
  }

  private buildLeavesFor(severity: SeverityKey): LiveFindingNode[] {
    return this.entries
      .filter((e) => severityKey(e.severity) === severity)
      .slice()
      .reverse()
      .map((e) => new LiveFindingNode(e))
  }
}

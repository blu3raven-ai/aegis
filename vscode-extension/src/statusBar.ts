/**
 * Manages the Aegis status bar item.
 *
 * Shows severity counts next to a shield icon.  A running scan is indicated
 * by a spinner prefix so the user knows the extension is active.
 */
import * as vscode from 'vscode'
import { Finding } from './client'

type ScanState = 'idle' | 'scanning' | 'done' | 'error'

export class StatusBarManager implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100,
    )
    this.item.command = 'aegis.scan'
    this.item.tooltip = 'Aegis Security Scanner — click to scan'
    this.setState('idle')
    this.item.show()
  }

  setState(state: ScanState, findings?: Finding[]): void {
    switch (state) {
      case 'idle':
        this.item.text = '$(shield) Aegis'
        this.item.tooltip = 'Aegis: click to scan'
        this.item.backgroundColor = undefined
        break

      case 'scanning':
        this.item.text = '$(sync~spin) Aegis: scanning…'
        this.item.tooltip = 'Aegis: scan in progress'
        this.item.backgroundColor = undefined
        break

      case 'done': {
        const counts = countBySeverity(findings ?? [])
        this.item.text = formatCounts(counts)
        this.item.tooltip = `Aegis: ${findings?.length ?? 0} finding(s) — click to re-scan`
        this.item.backgroundColor =
          counts.critical + counts.high > 0
            ? new vscode.ThemeColor('statusBarItem.errorBackground')
            : undefined
        break
      }

      case 'error':
        this.item.text = '$(shield) Aegis: error'
        this.item.tooltip = 'Aegis: last scan failed — check Output panel'
        this.item.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.errorBackground',
        )
        break
    }
  }

  dispose(): void {
    this.item.dispose()
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity]++
    }
  }
  return counts
}

function formatCounts(counts: SeverityCounts): string {
  const parts: string[] = ['$(shield) Aegis']

  if (counts.critical > 0) parts.push(`🔴 ${counts.critical}`)
  if (counts.high > 0) parts.push(`🟠 ${counts.high}`)
  if (counts.medium > 0) parts.push(`⚠️ ${counts.medium}`)
  if (counts.low > 0) parts.push(`ℹ️ ${counts.low}`)

  // When everything is clean, say so explicitly.
  if (counts.critical + counts.high + counts.medium + counts.low === 0) {
    parts.push('✓ clean')
  }

  return parts.join('  ')
}

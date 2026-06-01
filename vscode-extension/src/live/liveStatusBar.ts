/**
 * Status bar item for the live-findings stream.
 *
 * Three visual states, low-priority slot on the right:
 *   ● Aegis Live           — connected, no items yet
 *   ● Aegis Live (N)       — connected, N items in the view
 *   ○ Aegis Live           — disconnected
 *
 * The dot character is the only adornment — no spinner, no colour swap,
 * no notification.  PRODUCT.md: the surface should disappear into the task.
 */
import * as vscode from 'vscode'

export type LiveState = 'connected' | 'disconnected'

export function formatLiveStatus(state: LiveState, count: number): string {
  const glyph = state === 'connected' ? '●' : '○'
  const suffix = count > 0 ? ` (${count})` : ''
  return `${glyph} Aegis Live${suffix}`
}

export class LiveStatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem
  private state: LiveState = 'disconnected'
  private count = 0

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      50,
    )
    this.item.command = 'aegis.startLiveFindings'
    this.render()
    this.item.show()
  }

  setState(state: LiveState): void {
    this.state = state
    this.item.command =
      state === 'connected' ? 'aegis.stopLiveFindings' : 'aegis.startLiveFindings'
    this.render()
  }

  setCount(count: number): void {
    this.count = Math.max(0, count)
    this.render()
  }

  /** Read-only view of the rendered text — for tests. */
  text(): string {
    return this.item.text
  }

  private render(): void {
    this.item.text = formatLiveStatus(this.state, this.count)
    this.item.tooltip =
      this.state === 'connected'
        ? `Aegis Live findings: connected (${this.count} item${this.count === 1 ? '' : 's'}). Click to stop.`
        : 'Aegis Live findings: disconnected. Click to start.'
  }

  dispose(): void {
    this.item.dispose()
  }
}

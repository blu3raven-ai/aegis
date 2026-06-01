/**
 * "Aegis: Refresh Findings" — fetches the latest findings from the backend
 * without triggering a new scan run.
 *
 * Useful after a scan has already been queued (e.g. from CI) and you want
 * to pull results into the editor without waiting for another full scan.
 * Also used for the scanOnSave auto-refresh path.
 */
import * as vscode from 'vscode'
import { AegisClient } from '../client'
import { applyDiagnostics } from '../diagnostics'
import { FindingsTreeProvider } from '../findingsTreeProvider'
import { StatusBarManager } from '../statusBar'

export async function refresh(
  client: AegisClient,
  diagnostics: vscode.DiagnosticCollection,
  tree: FindingsTreeProvider,
  statusBar: StatusBarManager,
): Promise<void> {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
  if (!workspaceRoot) {
    return
  }

  statusBar.setState('scanning')

  try {
    const findings = await client.findings()
    applyDiagnostics(diagnostics, findings, workspaceRoot)
    tree.update(findings)
    statusBar.setState('done', findings)
  } catch (err) {
    statusBar.setState('error')
    // Refresh runs silently on save — avoid noisy pop-ups for transient errors.
    console.error(`[Aegis] Refresh failed: ${(err as Error).message}`)
  }
}

/**
 * "Aegis: Scan Current Repo" -- triggers a new scan and waits for results.
 *
 * This is intentionally the "expensive" command: it tells the CLI to run a
 * fresh scan against the backend.  Use refresh.ts to fetch cached findings
 * without triggering a new run.
 */
import * as vscode from 'vscode'
import { AegisClient, Finding } from '../client'
import { applyDiagnostics } from '../diagnostics'
import { FindingsTreeProvider } from '../findingsTreeProvider'
import { StatusBarManager } from '../statusBar'

export async function scan(
  client: AegisClient,
  diagnostics: vscode.DiagnosticCollection,
  tree: FindingsTreeProvider,
  statusBar: StatusBarManager,
): Promise<Finding[] | undefined> {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
  if (!workspaceRoot) {
    vscode.window.showErrorMessage('Aegis: No workspace folder open.')
    return undefined
  }

  statusBar.setState('scanning')

  try {
    const findings = await client.scan()
    applyDiagnostics(diagnostics, findings, workspaceRoot)
    tree.update(findings)
    statusBar.setState('done', findings)

    const critical = findings.filter((f) => f.severity === 'critical').length
    const high = findings.filter((f) => f.severity === 'high').length

    if (critical + high > 0) {
      vscode.window.showWarningMessage(
        `Aegis: Scan complete -- ${critical} critical, ${high} high severity findings.`,
        'View Problems',
      ).then((choice) => {
        if (choice === 'View Problems') {
          vscode.commands.executeCommand('workbench.panel.markers.view.focus')
        }
      })
    } else {
      vscode.window.showInformationMessage(
        `Aegis: Scan complete -- ${findings.length} finding(s).`,
      )
    }

    return findings
  } catch (err) {
    statusBar.setState('error')
    vscode.window.showErrorMessage(`Aegis scan failed: ${(err as Error).message}`)
    return undefined
  }
}

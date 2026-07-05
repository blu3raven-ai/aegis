/**
 * "Aegis: Rescan with Latest Rules" — invalidates cached findings and
 * re-runs SAST against the full workspace using the current rule pack.
 *
 * Useful immediately after a rule-pack release so the team can see whether
 * previously clean code is flagged by new rules, without waiting for the
 * next CI pipeline run.
 */
import * as vscode from 'vscode'
import { AegisClient, Finding } from '../client'
import { applyDiagnostics } from '../diagnostics'
import { FindingsTreeProvider } from '../findingsTreeProvider'
import { StatusBarManager } from '../statusBar'
import { getChannel, log } from '../output'

export async function rescanLatest(
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

  const channel = getChannel()
  channel.show(true)
  log('Starting rescan with latest rules (cache invalidated)')

  statusBar.setState('scanning')

  try {
    const findings = await client.scanScope({ forceRefreshRules: true })
    applyDiagnostics(diagnostics, findings, workspaceRoot)
    tree.update(findings)
    statusBar.setState('done', findings)

    log(`Rescan complete: ${findings.length} findings`)

    const critical = findings.filter((f) => f.severity === 'critical').length
    const high = findings.filter((f) => f.severity === 'high').length

    if (critical + high > 0) {
      vscode.window.showWarningMessage(
        `Aegis: Rescan complete — ${critical} critical, ${high} high severity findings.`,
        'View Problems',
      ).then((choice) => {
        if (choice === 'View Problems') {
          vscode.commands.executeCommand('workbench.panel.markers.view.focus')
        }
      })
    } else {
      vscode.window.showInformationMessage(
        `Aegis: Rescan complete — ${findings.length} finding(s).`,
      )
    }

    return findings
  } catch (err) {
    log(`Rescan failed: ${err}`, 'error')
    statusBar.setState('error')
    vscode.window.showErrorMessage(`Aegis rescan failed: ${(err as Error).message}`)
    return undefined
  }
}

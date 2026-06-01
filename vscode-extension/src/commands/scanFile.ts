/**
 * "Aegis: Scan This File" — runs a SAST scan scoped to a single file.
 *
 * Registered on both the explorer context menu (right-click a file) and the
 * editor title context menu so it's reachable without leaving the active tab.
 */
import * as vscode from 'vscode'
import { AegisClient } from '../client'
import { getChannel, log } from '../output'

export async function scanFile(client: AegisClient, uri?: vscode.Uri): Promise<void> {
  // Fall back to the active editor when invoked from the editor title bar.
  const target = uri ?? vscode.window.activeTextEditor?.document.uri

  if (!target) {
    vscode.window.showErrorMessage('Aegis: No file selected — open a file or right-click one in the Explorer.')
    return
  }

  const channel = getChannel()
  channel.show(true)
  log(`Scanning file: ${target.fsPath}`)

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Aegis: Scanning file…',
      cancellable: true,
    },
    async (_progress, _token) => {
      try {
        const findings = await client.scanScope({ filePath: target.fsPath })
        log(`File scan complete: ${findings.length} findings`)

        const fileName = target.fsPath.split('/').pop() ?? target.fsPath
        vscode.window.showInformationMessage(
          `Aegis: ${findings.length} finding(s) in ${fileName}`,
        )
      } catch (e) {
        log(`File scan failed: ${e}`, 'error')
        vscode.window.showErrorMessage(`Aegis scan failed: ${(e as Error).message}`)
      }
    },
  )
}

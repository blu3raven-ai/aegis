/**
 * "Aegis: Scan This Folder" — runs a SAST scan scoped to the right-clicked
 * folder rather than the entire workspace.
 *
 * Scoping reduces scan time for large monorepos where only one sub-tree has
 * changed.  Results are merged into the workspace-wide diagnostic collection
 * so the Problems panel always shows a complete picture.
 */
import * as vscode from 'vscode'
import { AegisClient } from '../client'
import { getChannel, log } from '../output'

export async function scanFolder(client: AegisClient, uri?: vscode.Uri): Promise<void> {
  if (!uri) {
    vscode.window.showErrorMessage('Aegis: Please right-click a folder to scan.')
    return
  }

  const channel = getChannel()
  channel.show(true)
  log(`Scanning folder: ${uri.fsPath}`)

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Aegis: Scanning folder…',
      cancellable: true,
    },
    async (_progress, _token) => {
      try {
        const findings = await client.scanScope({ folderPath: uri.fsPath })
        log(`Folder scan complete: ${findings.length} findings`)

        const folderName = uri.fsPath.split('/').pop() ?? uri.fsPath
        vscode.window.showInformationMessage(
          `Aegis: ${findings.length} finding(s) in ${folderName}`,
        )
      } catch (e) {
        log(`Folder scan failed: ${e}`, 'error')
        vscode.window.showErrorMessage(`Aegis scan failed: ${(e as Error).message}`)
      }
    },
  )
}

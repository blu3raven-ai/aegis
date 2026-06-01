/**
 * "Aegis: Check Decision" — asks the backend for a go/no-go deployment
 * decision and surfaces the result as a VSCode notification.
 *
 * This mirrors what the CI gate does via `aegis decide --exit-code` but
 * brings the answer into the developer's editor before they push.
 */
import * as vscode from 'vscode'
import { AegisClient } from '../client'

export async function decide(client: AegisClient): Promise<void> {
  try {
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Aegis: Checking deployment decision…',
        cancellable: false,
      },
      async () => {
        const result = await client.decide()

        const blockerCount = result.blockers?.length ?? 0
        const msg = `Aegis decision: ${result.decision.toUpperCase()} — ${result.rationale}`

        switch (result.decision) {
          case 'block':
            vscode.window.showErrorMessage(
              `${msg} (${blockerCount} blocker(s))`,
            )
            break
          case 'warn':
            vscode.window.showWarningMessage(msg)
            break
          case 'allow':
          default:
            vscode.window.showInformationMessage(msg)
            break
        }
      },
    )
  } catch (err) {
    vscode.window.showErrorMessage(
      `Aegis: Decision check failed — ${(err as Error).message}`,
    )
  }
}

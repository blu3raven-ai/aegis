/**
 * "Aegis: Mark as Fixed" — tells the backend the finding has been remediated.
 *
 * This is a developer convenience: it flags the finding as resolved without
 * requiring a full re-scan.  The backend will verify on the next scan run.
 */
import * as vscode from 'vscode'
import { AegisClient } from '../client'

export async function markFixed(
  client: AegisClient,
  findingId: string,
): Promise<void> {
  try {
    await client.markFixedFinding(findingId)
    vscode.window.showInformationMessage(
      `Aegis: Finding marked as fixed.`,
    )
  } catch (err) {
    vscode.window.showErrorMessage(
      `Aegis: Failed to mark finding as fixed — ${(err as Error).message}`,
    )
  }
}

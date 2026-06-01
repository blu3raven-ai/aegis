/**
 * "Aegis: Snooze Finding" — marks a finding as snoozed for N days.
 *
 * Snoozing suppresses the diagnostic from the Problems panel and the sidebar
 * tree until the snooze period expires on the backend.
 */
import * as vscode from 'vscode'
import { AegisClient } from '../client'

const DEFAULT_SNOOZE_DAYS = 7

export async function snoozeFinding(
  client: AegisClient,
  findingId: string,
  durationDays: number = DEFAULT_SNOOZE_DAYS,
): Promise<void> {
  try {
    await client.snoozeFinding(findingId, durationDays)
    vscode.window.showInformationMessage(
      `Aegis: Finding snoozed for ${durationDays} day${durationDays !== 1 ? 's' : ''}.`,
    )
  } catch (err) {
    vscode.window.showErrorMessage(
      `Aegis: Failed to snooze finding — ${(err as Error).message}`,
    )
  }
}

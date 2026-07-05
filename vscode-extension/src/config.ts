/**
 * Typed accessors for the aegis.* workspace configuration block.
 *
 * Keeping all settings reads in one place makes it easy to swap the
 * configuration layer (e.g. SecretStorage for tokens) without touching
 * command logic.
 */
import * as vscode from 'vscode'

export interface AegisConfig {
  cliPath: string
  baseUrl: string
  apiToken: string
  org: string
  scanOnSave: boolean
}

export function getConfig(): AegisConfig {
  const cfg = vscode.workspace.getConfiguration('aegis')
  return {
    cliPath: cfg.get<string>('cliPath') ?? 'aegis',
    baseUrl: cfg.get<string>('baseUrl') ?? '',
    apiToken: cfg.get<string>('apiToken') ?? '',
    org: cfg.get<string>('org') ?? '',
    scanOnSave: cfg.get<boolean>('scanOnSave') ?? false,
  }
}

/**
 * "Aegis: Show Chain" — opens the chain graph webview for a finding's chain.
 *
 * Can be triggered from the command palette (prompts for chainId) or from a
 * code action which passes the chainId directly.
 */
import * as vscode from 'vscode'
import { AegisClient } from '../client'
import { ChainWebviewPanel } from '../webviews/chainWebview'

export async function showChain(
  client: AegisClient,
  extensionUri: vscode.Uri,
  chainId?: string,
): Promise<void> {
  const id = chainId ?? await promptForChainId()
  if (!id) return

  // Start the fetch immediately so the webview can show a loading state.
  const chainPromise = client.getChain(id)
  ChainWebviewPanel.open(extensionUri, id, chainPromise)
}

async function promptForChainId(): Promise<string | undefined> {
  return vscode.window.showInputBox({
    prompt: 'Enter chain ID',
    placeHolder: 'e.g. chain-abc123',
    validateInput: (v) => (v.trim() ? undefined : 'Chain ID cannot be empty'),
  })
}

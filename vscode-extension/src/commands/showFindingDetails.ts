/**
 * "Aegis: Show Finding Details" — opens a read-only virtual document with
 * full finding metadata formatted for readability.
 *
 * Uses a virtual document provider rather than a webview so the content is
 * lightweight and supports native VSCode search/copy behaviour.
 */
import * as vscode from 'vscode'
import { Finding } from '../client'

// In-memory store of detail documents keyed by finding ID.
const detailStore = new Map<string, string>()

class FindingDetailProvider implements vscode.TextDocumentContentProvider {
  provideTextDocumentContent(uri: vscode.Uri): string {
    return detailStore.get(uri.path) ?? '(no details available)'
  }
}

let providerRegistered = false
let _provider: FindingDetailProvider | undefined

export function registerFindingDetailProvider(
  context: vscode.ExtensionContext,
): void {
  if (providerRegistered) return
  _provider = new FindingDetailProvider()
  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider(
      'aegis-finding',
      _provider,
    ),
  )
  providerRegistered = true
}

export async function showFindingDetails(finding: Finding): Promise<void> {
  const content = formatFinding(finding)
  detailStore.set(finding.id, content)

  const uri = vscode.Uri.parse(`aegis-finding:${finding.id}`)
  const doc = await vscode.workspace.openTextDocument(uri)
  await vscode.window.showTextDocument(doc, {
    preview: true,
    viewColumn: vscode.ViewColumn.Beside,
  })
}

function formatFinding(f: Finding): string {
  const lines: string[] = [
    `┌─ Aegis Finding ────────────────────────────────────────────┐`,
    ``,
    `  ID:        ${f.id}`,
    `  Severity:  ${f.severity.toUpperCase()}`,
    `  Rule:      ${f.ruleId}`,
    `  Scanner:   ${f.scanner}`,
    `  File:      ${f.filePath}`,
    `  Line:      ${f.line}`,
    ``,
    `  Message:`,
    `    ${f.message}`,
    ``,
  ]

  if (f.chainId) {
    lines.push(`  Chain:     ${f.chainId}`)
    lines.push(``)
  }

  lines.push(`└────────────────────────────────────────────────────────────┘`)
  return lines.join('\n')
}

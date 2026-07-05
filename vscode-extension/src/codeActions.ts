/**
 * AegisCodeActionProvider — surfaces quick-fix actions on Aegis diagnostics.
 *
 * Registered for all document types (`*`) because Aegis diagnostics can appear
 * on any file language.  Actions are only produced when the cursor range
 * intersects an Aegis diagnostic.
 */
import * as vscode from 'vscode'
import { Finding } from './client'

export class AegisCodeActionProvider implements vscode.CodeActionProvider {
  // Updated whenever findings are refreshed so actions have current data.
  private findings: Finding[] = []

  update(findings: Finding[]): void {
    this.findings = findings
  }

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const aegisDiags = context.diagnostics.filter(
      (d) => d.source?.startsWith('aegis/'),
    )
    if (aegisDiags.length === 0) return []

    const actions: vscode.CodeAction[] = []

    for (const diag of aegisDiags) {
      // Match diagnostic back to its Finding by ruleId + line number.
      const finding = this.findingForDiagnostic(document, diag)
      if (!finding) continue

      // Show Finding Details — always available.
      actions.push(
        buildAction(
          `Aegis: Show details for ${finding.ruleId}`,
          vscode.CodeActionKind.QuickFix,
          { command: 'aegis.showFindingDetails', title: 'Show Finding Details', arguments: [finding] },
        ),
      )

      // Show Chain — only when the finding belongs to a chain.
      if (finding.chainId) {
        actions.push(
          buildAction(
            `Aegis: Show attack chain (${finding.chainId})`,
            vscode.CodeActionKind.QuickFix,
            { command: 'aegis.showChain', title: 'Show Chain', arguments: [finding.chainId] },
          ),
        )
      }

      // Snooze for 7 days.
      actions.push(
        buildAction(
          `Aegis: Snooze finding for 7 days`,
          vscode.CodeActionKind.QuickFix,
          { command: 'aegis.snoozeFinding', title: 'Snooze for 7 days', arguments: [finding.id, 7] },
        ),
      )

      // Mark as Fixed.
      actions.push(
        buildAction(
          `Aegis: Mark finding as fixed`,
          vscode.CodeActionKind.QuickFix,
          { command: 'aegis.markFixed', title: 'Mark as Fixed', arguments: [finding.id] },
        ),
      )
    }

    return actions
  }

  private findingForDiagnostic(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
  ): Finding | undefined {
    const fsPath = document.uri.fsPath
    const lineOneBased = diag.range.start.line + 1
    const ruleId = typeof diag.code === 'string' ? diag.code : String(diag.code ?? '')

    return this.findings.find(
      (f) =>
        (f.filePath === fsPath || fsPath.endsWith(f.filePath)) &&
        f.line === lineOneBased &&
        f.ruleId === ruleId,
    )
  }
}

function buildAction(
  title: string,
  kind: vscode.CodeActionKind,
  command: vscode.Command,
): vscode.CodeAction {
  const action = new vscode.CodeAction(title, kind)
  action.command = command
  return action
}

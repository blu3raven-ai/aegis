/**
 * Converts Aegis findings into VSCode Diagnostics so they appear inline
 * in the editor gutter and in the Problems panel.
 *
 * The severity mapping intentionally collapses critical+high → Error and
 * medium → Warning because VSCode's DiagnosticSeverity has no "critical"
 * tier.  The original severity label is preserved in the source string so
 * users can distinguish critical from high in the Problems panel tooltip.
 */
import * as path from 'path'
import * as vscode from 'vscode'
import { Finding } from './client'

export function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
  workspaceRoot: string,
): void {
  collection.clear()

  const byFile = new Map<string, vscode.Diagnostic[]>()

  for (const f of findings) {
    const absPath = path.isAbsolute(f.filePath)
      ? f.filePath
      : path.join(workspaceRoot, f.filePath)
    const fileUri = vscode.Uri.file(absPath)
    const uriKey = fileUri.toString()

    // Lines from the CLI are 1-based; VSCode Ranges are 0-based.
    const lineIndex = Math.max(0, f.line - 1)
    const range = new vscode.Range(lineIndex, 0, lineIndex, Number.MAX_SAFE_INTEGER)
    const diag = new vscode.Diagnostic(range, f.message, severityToVscode(f.severity))
    diag.source = `aegis/${f.scanner} [${f.severity}]`
    diag.code = f.ruleId

    if (!byFile.has(uriKey)) {
      byFile.set(uriKey, [])
    }
    byFile.get(uriKey)!.push(diag)
  }

  for (const [uriKey, diags] of byFile) {
    collection.set(vscode.Uri.parse(uriKey), diags)
  }
}

export function severityToVscode(severity: Finding['severity']): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error
    case 'medium':
      return vscode.DiagnosticSeverity.Warning
    case 'low':
      return vscode.DiagnosticSeverity.Information
    default:
      return vscode.DiagnosticSeverity.Hint
  }
}

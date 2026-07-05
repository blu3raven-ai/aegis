/**
 * VSCode extension entry point -- activate() wires together all subsystems.
 *
 * Subsystems are kept as thin singletons; commands are the only integration
 * point between them so each module stays testable in isolation.
 */
import * as vscode from 'vscode'
import { AegisClient, Finding } from './client'
import { FindingsTreeProvider } from './findingsTreeProvider'
import { StatusBarManager } from './statusBar'
import { AegisCodeActionProvider } from './codeActions'
import { getConfig } from './config'
import { scan } from './commands/scan'
import { decide } from './commands/decide'
import { showChain } from './commands/showChain'
import { snoozeFinding } from './commands/snooze'
import { markFixed } from './commands/markFixed'
import {
  showFindingDetails,
  registerFindingDetailProvider,
} from './commands/showFindingDetails'
import { scanFolder } from './commands/scanFolder'
import { scanFile } from './commands/scanFile'
import { rescanLatest } from './commands/rescanLatest'
import { LiveFindingsTreeProvider } from './live/liveFindingsTreeProvider'
import { LiveStatusBar } from './live/liveStatusBar'
import { LiveSession } from './live/liveSession'

export function activate(context: vscode.ExtensionContext): void {
  const config = getConfig()
  const client = new AegisClient(config)
  const diagnostics = vscode.languages.createDiagnosticCollection('aegis')
  const tree = new FindingsTreeProvider()
  const statusBar = new StatusBarManager()
  const codeActionProvider = new AegisCodeActionProvider()

  // Virtual document provider for finding detail views.
  registerFindingDetailProvider(context)

  vscode.window.registerTreeDataProvider('aegis.findings', tree)

  const liveTree = new LiveFindingsTreeProvider()
  const liveStatusBar = new LiveStatusBar()
  const liveSession = new LiveSession(liveTree, liveStatusBar, getConfig)
  vscode.window.registerTreeDataProvider('aegis.liveFindings', liveTree)
  context.subscriptions.push(liveSession)

  // Code action provider registered for all file types -- Aegis findings can
  // appear on any language.
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider('*', codeActionProvider, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
  )

  const { applyDiagnostics } = require('./diagnostics')

  // Keep the code action provider in sync with the latest findings.
  const refreshAndSync = async (): Promise<void> => {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
    if (!workspaceRoot) return
    statusBar.setState('scanning')
    try {
      const findings: Finding[] = await client.findings()
      applyDiagnostics(diagnostics, findings, workspaceRoot)
      tree.update(findings)
      codeActionProvider.update(findings)
      statusBar.setState('done', findings)
    } catch (err) {
      statusBar.setState('error')
      console.error(`[Aegis] Refresh failed: ${(err as Error).message}`)
    }
  }

  context.subscriptions.push(
    diagnostics,
    statusBar,

    vscode.commands.registerCommand('aegis.scan', async () => {
      const findings = await scan(client, diagnostics, tree, statusBar)
      if (findings) codeActionProvider.update(findings)
    }),

    vscode.commands.registerCommand('aegis.refresh', refreshAndSync),

    vscode.commands.registerCommand('aegis.decide', () => decide(client)),

    vscode.commands.registerCommand(
      'aegis.showChain',
      (chainId?: string) => showChain(client, context.extensionUri, chainId),
    ),

    vscode.commands.registerCommand(
      'aegis.snoozeFinding',
      (findingId: string, durationDays?: number) =>
        snoozeFinding(client, findingId, durationDays),
    ),

    vscode.commands.registerCommand(
      'aegis.markFixed',
      (findingId: string) => markFixed(client, findingId),
    ),

    vscode.commands.registerCommand(
      'aegis.showFindingDetails',
      (finding: Finding) => showFindingDetails(finding),
    ),

    vscode.commands.registerCommand(
      'aegis.scanFolder',
      (uri?: vscode.Uri) => scanFolder(client, uri),
    ),

    vscode.commands.registerCommand(
      'aegis.scanFile',
      (uri?: vscode.Uri) => scanFile(client, uri),
    ),

    vscode.commands.registerCommand(
      'aegis.rescanWithLatestRules',
      () => rescanLatest(client, diagnostics, tree, statusBar),
    ),

    vscode.commands.registerCommand('aegis.startLiveFindings', () => {
      liveSession.start()
    }),

    vscode.commands.registerCommand('aegis.stopLiveFindings', () => {
      liveSession.stop()
    }),

    vscode.commands.registerCommand('aegis.clearLiveFindings', () => {
      liveSession.clear()
    }),
  )

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('aegis')) {
        // scanOnSave changes require a window reload; all others are read fresh.
      }
    }),
  )

  if (config.scanOnSave) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(refreshAndSync),
    )
  }
}

export function deactivate(): void {
  // Nothing to clean up -- all disposables are registered via context.subscriptions.
}

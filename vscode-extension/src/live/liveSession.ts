/**
 * Orchestrator that ties the SSE client, the live findings tree, and the
 * live status bar into a single session.  One session per extension host.
 *
 * Start: open an SSE stream, route every finding event into the tree and
 * tick the status bar count.  Stop: tear down the stream, mark
 * disconnected, leave the tree alone (user can re-clear if they want).
 */
import * as vscode from 'vscode'
import { AegisConfig } from '../config'
import { log } from '../output'
import { connectSse, FindingEvent, SseConnection } from './sseClient'
import { LiveFindingsTreeProvider } from './liveFindingsTreeProvider'
import { LiveStatusBar } from './liveStatusBar'

export class LiveSession implements vscode.Disposable {
  private connection: SseConnection | null = null

  constructor(
    private readonly tree: LiveFindingsTreeProvider,
    private readonly statusBar: LiveStatusBar,
    private readonly getConfigFn: () => AegisConfig,
  ) {}

  isConnected(): boolean {
    return this.connection !== null
  }

  start(): void {
    if (this.connection) return

    const config = this.getConfigFn()
    if (!config.baseUrl) {
      void vscode.window.showErrorMessage(
        'Aegis: set "aegis.baseUrl" before starting the live findings stream.',
      )
      return
    }

    log('Live findings: connecting to SSE stream')

    this.connection = connectSse({
      baseUrl: config.baseUrl,
      apiToken: config.apiToken || undefined,
      onOpen: () => {
        this.statusBar.setState('connected')
        log('Live findings: connected')
      },
      onEvent: (event: FindingEvent) => {
        this.tree.add(event)
        this.statusBar.setCount(this.tree.size())
      },
      onClose: () => {
        this.statusBar.setState('disconnected')
        this.connection = null
        log('Live findings: stream closed')
      },
      onError: (err: Error) => {
        this.statusBar.setState('disconnected')
        this.connection = null
        log(`Live findings: ${err.message}`, 'error')
        void vscode.window.showErrorMessage(`Aegis live findings: ${err.message}`)
      },
    })
  }

  stop(): void {
    if (!this.connection) {
      this.statusBar.setState('disconnected')
      return
    }
    const conn = this.connection
    this.connection = null
    conn.close()
    this.statusBar.setState('disconnected')
    this.tree.clear()
    this.statusBar.setCount(0)
    log('Live findings: stopped')
  }

  clear(): void {
    this.tree.clear()
    this.statusBar.setCount(0)
  }

  dispose(): void {
    if (this.connection) {
      const conn = this.connection
      this.connection = null
      conn.close()
    }
    this.statusBar.dispose()
  }
}

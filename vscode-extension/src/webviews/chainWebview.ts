/**
 * ChainWebviewPanel — manages a single VSCode WebviewPanel for chain graphs.
 *
 * One panel per chain ID is kept alive; re-opening the same chain brings the
 * existing panel to the foreground rather than creating a duplicate.
 */
import * as path from 'path'
import * as fs from 'fs'
import * as vscode from 'vscode'
import { Chain } from '../client'

export class ChainWebviewPanel {
  // Track open panels by chainId so we can reuse them.
  private static readonly openPanels = new Map<string, ChainWebviewPanel>()

  private readonly panel: vscode.WebviewPanel
  private readonly extensionUri: vscode.Uri
  private chainId: string

  static open(
    extensionUri: vscode.Uri,
    chainId: string,
    chainPromise: Promise<Chain>,
  ): void {
    const existing = ChainWebviewPanel.openPanels.get(chainId)
    if (existing) {
      existing.panel.reveal(vscode.ViewColumn.Beside)
      existing.sendChain(chainPromise)
      return
    }
    new ChainWebviewPanel(extensionUri, chainId, chainPromise)
  }

  private constructor(
    extensionUri: vscode.Uri,
    chainId: string,
    chainPromise: Promise<Chain>,
  ) {
    this.extensionUri = extensionUri
    this.chainId = chainId

    this.panel = vscode.window.createWebviewPanel(
      'aegis.chainGraph',
      `Chain: ${chainId}`,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [
          vscode.Uri.joinPath(extensionUri, 'media'),
        ],
        retainContextWhenHidden: true,
      },
    )

    this.panel.webview.html = this.buildHtml()

    // Wait for the webview to signal readiness, then push chain data.
    this.panel.webview.onDidReceiveMessage((msg) => {
      if (msg.type === 'ready') {
        this.sendChain(chainPromise)
      }
    })

    this.panel.onDidDispose(() => {
      ChainWebviewPanel.openPanels.delete(this.chainId)
    })

    ChainWebviewPanel.openPanels.set(chainId, this)
  }

  private sendChain(chainPromise: Promise<Chain>): void {
    chainPromise
      .then((chain) => {
        this.panel.title = `Chain: ${chain.title || this.chainId}`
        this.panel.webview.postMessage({ type: 'load', chain })
      })
      .catch((err) => {
        this.panel.webview.postMessage({
          type: 'error',
          message: (err as Error).message,
        })
      })
  }

  private buildHtml(): string {
    const nonce = generateNonce()
    const mediaDir = path.join(this.extensionUri.fsPath, 'media')

    // Read the HTML template from disk so it doesn't need to be embedded as a string.
    const templatePath = path.join(mediaDir, 'chain-graph.html')
    let html = fs.readFileSync(templatePath, 'utf8')

    const cssUri = this.panel.webview.asWebviewUri(
      vscode.Uri.joinPath(this.extensionUri, 'media', 'chain-graph.css'),
    )
    const jsUri = this.panel.webview.asWebviewUri(
      vscode.Uri.joinPath(this.extensionUri, 'media', 'chain-graph.js'),
    )

    html = html
      .replace(/\{\{NONCE\}\}/g, nonce)
      .replace('{{CSP_SOURCE}}', this.panel.webview.cspSource)
      .replace('{{CSS_URI}}', cssUri.toString())
      .replace('{{JS_URI}}', jsUri.toString())

    return html
  }
}

function generateNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let nonce = ''
  for (let i = 0; i < 32; i++) {
    nonce += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return nonce
}

/**
 * Tests for the chain graph webview.
 *
 * The ChainWebviewPanel relies on the VSCode API at runtime, so these tests
 * exercise the HTML generation logic and nonce behaviour in isolation using
 * the shared vscode stub.
 */
import assert from 'assert'
import * as fs from 'fs'
import * as path from 'path'
// Must be first so the vscode mock is in place before any extension source loads.
import './setup'

// When tests run from out/tests/, __dirname resolves there.
// The media files live at the project root (not under out/).
const projectRoot = path.join(__dirname, '..', '..')

describe('chain-graph.html template', () => {
  const templatePath = path.join(projectRoot, 'media', 'chain-graph.html')

  it('template file exists', () => {
    assert.ok(fs.existsSync(templatePath), `Expected template at ${templatePath}`)
  })

  it('contains nonce placeholder', () => {
    const html = fs.readFileSync(templatePath, 'utf8')
    assert.ok(html.includes('{{NONCE}}'), 'Template must have {{NONCE}} placeholder')
  })

  it('contains CSS URI placeholder', () => {
    const html = fs.readFileSync(templatePath, 'utf8')
    assert.ok(html.includes('{{CSS_URI}}'), 'Template must have {{CSS_URI}} placeholder')
  })

  it('contains JS URI placeholder', () => {
    const html = fs.readFileSync(templatePath, 'utf8')
    assert.ok(html.includes('{{JS_URI}}'), 'Template must have {{JS_URI}} placeholder')
  })

  it('contains CSP meta tag', () => {
    const html = fs.readFileSync(templatePath, 'utf8')
    assert.ok(html.includes('Content-Security-Policy'), 'Template must have a CSP meta tag')
  })

  it('script tag carries nonce attribute', () => {
    const html = fs.readFileSync(templatePath, 'utf8')
    assert.ok(html.includes('nonce="{{NONCE}}"'), 'Script tag must carry nonce attribute')
  })

  it('template renders without placeholder tokens after substitution', () => {
    const html = fs.readFileSync(templatePath, 'utf8')
    const rendered = html
      .replace(/\{\{NONCE\}\}/g, 'test-nonce-123')
      .replace('{{CSP_SOURCE}}', 'vscode-resource:')
      .replace('{{CSS_URI}}', 'vscode-resource:/media/chain-graph.css')
      .replace('{{JS_URI}}', 'vscode-resource:/media/chain-graph.js')
    assert.ok(!rendered.includes('{{'), 'No unresolved {{ placeholders should remain')
  })
})

describe('chain-graph.js', () => {
  const jsPath = path.join(projectRoot, 'media', 'chain-graph.js')

  it('file exists', () => {
    assert.ok(fs.existsSync(jsPath), `Expected JS at ${jsPath}`)
  })

  it('uses acquireVsCodeApi()', () => {
    const src = fs.readFileSync(jsPath, 'utf8')
    assert.ok(src.includes('acquireVsCodeApi'), 'chain-graph.js must call acquireVsCodeApi()')
  })

  it("handles 'load' message type", () => {
    const src = fs.readFileSync(jsPath, 'utf8')
    assert.ok(src.includes("case 'load'"), "Must handle 'load' message")
  })

  it("handles 'error' message type", () => {
    const src = fs.readFileSync(jsPath, 'utf8')
    assert.ok(src.includes("case 'error'"), "Must handle 'error' message")
  })

  it("posts 'ready' message on startup", () => {
    const src = fs.readFileSync(jsPath, 'utf8')
    assert.ok(src.includes("type: 'ready'"), "Must post 'ready' message to extension host")
  })
})

describe('ChainWebviewPanel', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { ChainWebviewPanel } = require('../src/webviews/chainWebview')

  it('exposes a static open() method', () => {
    assert.strictEqual(typeof ChainWebviewPanel.open, 'function')
  })

  it('open() creates a panel without throwing when given a mock extensionUri', () => {
    const mockExtensionUri = {
      fsPath: path.join(__dirname, '..', '..'),
      toString: () => `file://${path.join(__dirname, '..', '..')}`,
    }
    const mockChainPromise = Promise.resolve({
      id: 'chain-1',
      title: 'Test Chain',
      nodes: [{ id: 'n1', label: 'Node 1', type: 'finding', severity: 'high' }],
      edges: [],
    })
    assert.doesNotThrow(() => {
      ChainWebviewPanel.open(mockExtensionUri, 'chain-1', mockChainPromise)
    })
  })
})

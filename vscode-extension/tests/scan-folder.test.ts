/**
 * Unit tests for the scanFolder, scanFile, and rescanLatest commands.
 *
 * Uses the shared vscode mock so no live VS Code instance is required.
 * Client methods are stubbed to avoid spawning the aegis CLI.
 */
import assert from 'assert'
// Must be first so the vscode mock is in place before any extension source loads.
import './setup'
import { vscodeMock } from './setup'

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { scanFolder } = require('../src/commands/scanFolder')
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { scanFile } = require('../src/commands/scanFile')
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { rescanLatest } = require('../src/commands/rescanLatest')

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeUri(fsPath: string) {
  return { fsPath, toString: () => `file://${fsPath}` }
}

function makeFindings(n = 2) {
  return Array.from({ length: n }, (_, i) => ({
    id: `finding-${i}`,
    filePath: `/workspace/src/file${i}.py`,
    line: i + 1,
    severity: 'high',
    ruleId: `R00${i}`,
    message: `issue ${i}`,
    scanner: 'sast',
  }))
}

function makeClient(overrides: Record<string, unknown> = {}) {
  return {
    scanScope: async () => makeFindings(),
    ...overrides,
  }
}

function makeDiagnosticCollection() {
  const calls: unknown[] = []
  return {
    clear: () => {},
    set: (...args: unknown[]) => calls.push(args),
    _calls: calls,
  }
}

function makeTree() {
  const updates: unknown[] = []
  return {
    update: (findings: unknown) => updates.push(findings),
    _updates: updates,
  }
}

function makeStatusBar() {
  const states: string[] = []
  return {
    setState: (state: string) => states.push(state),
    _states: states,
  }
}

// ── scanFolder ────────────────────────────────────────────────────────────────

describe('scanFolder()', () => {
  let errorMessages: string[]

  beforeEach(() => {
    errorMessages = []
    vscodeMock.window.showErrorMessage = (msg: string) => {
      errorMessages.push(msg)
      return Promise.resolve(undefined)
    }
  })

  it('shows error and returns when no URI provided', async () => {
    const client = makeClient()
    await scanFolder(client, undefined)
    assert.ok(errorMessages.some((m: string) => m.includes('right-click a folder')))
  })

  it('calls client.scanScope with folderPath', async () => {
    const calls: unknown[] = []
    const client = makeClient({
      scanScope: async (opts: unknown) => { calls.push(opts); return makeFindings(3) },
    })

    await scanFolder(client, makeUri('/workspace/src'))

    assert.strictEqual(calls.length, 1)
    assert.deepStrictEqual(calls[0], { folderPath: '/workspace/src' })
  })

  it('shows information message with finding count on success', async () => {
    const infos: string[] = []
    vscodeMock.window.showInformationMessage = (msg: string) => { infos.push(msg); return Promise.resolve(undefined) }

    const client = makeClient({ scanScope: async () => makeFindings(5) })
    await scanFolder(client, makeUri('/workspace/src'))

    assert.ok(infos.some((m: string) => m.includes('5')))
  })

  it('shows error message when client throws', async () => {
    const errors: string[] = []
    vscodeMock.window.showErrorMessage = (msg: string) => { errors.push(msg); return Promise.resolve(undefined) }

    const client = makeClient({
      scanScope: async () => { throw new Error('CLI not found') },
    })
    await scanFolder(client, makeUri('/workspace/src'))

    assert.ok(errors.some((m: string) => m.includes('CLI not found')))
  })
})

// ── scanFile ──────────────────────────────────────────────────────────────────

describe('scanFile()', () => {
  let errorMessages: string[]

  beforeEach(() => {
    errorMessages = []
    vscodeMock.window.showErrorMessage = (msg: string) => {
      errorMessages.push(msg)
      return Promise.resolve(undefined)
    }
    // No active editor by default.
    vscodeMock.window.activeTextEditor = undefined
  })

  it('shows error when no URI and no active editor', async () => {
    const client = makeClient()
    await scanFile(client, undefined)
    assert.ok(errorMessages.some((m: string) => m.includes('No file selected')))
  })

  it('calls client.scanScope with filePath when URI provided', async () => {
    const calls: unknown[] = []
    const client = makeClient({
      scanScope: async (opts: unknown) => { calls.push(opts); return makeFindings(1) },
    })

    await scanFile(client, makeUri('/workspace/src/vuln.py'))

    assert.strictEqual(calls.length, 1)
    assert.deepStrictEqual(calls[0], { filePath: '/workspace/src/vuln.py' })
  })

  it('falls back to active editor URI when no explicit URI given', async () => {
    const calls: unknown[] = []
    const client = makeClient({
      scanScope: async (opts: unknown) => { calls.push(opts); return makeFindings(0) },
    })

    vscodeMock.window.activeTextEditor = { document: { uri: makeUri('/workspace/src/active.py') } }
    await scanFile(client, undefined)

    assert.strictEqual(calls.length, 1)
    assert.deepStrictEqual(calls[0], { filePath: '/workspace/src/active.py' })
  })

  it('shows information message with finding count on success', async () => {
    const infos: string[] = []
    vscodeMock.window.showInformationMessage = (msg: string) => { infos.push(msg); return Promise.resolve(undefined) }

    const client = makeClient({ scanScope: async () => makeFindings(2) })
    await scanFile(client, makeUri('/workspace/src/file.py'))

    assert.ok(infos.some((m: string) => m.includes('2')))
  })

  it('shows error message when client throws', async () => {
    const errors: string[] = []
    vscodeMock.window.showErrorMessage = (msg: string) => { errors.push(msg); return Promise.resolve(undefined) }

    const client = makeClient({
      scanScope: async () => { throw new Error('scan failed') },
    })
    await scanFile(client, makeUri('/workspace/src/file.py'))

    assert.ok(errors.some((m: string) => m.includes('scan failed')))
  })
})

// ── rescanLatest ──────────────────────────────────────────────────────────────

describe('rescanLatest()', () => {
  it('calls client.scanScope with forceRefreshRules: true', async () => {
    const calls: unknown[] = []
    const client = makeClient({
      scanScope: async (opts: unknown) => { calls.push(opts); return makeFindings(2) },
    })

    await rescanLatest(client, makeDiagnosticCollection(), makeTree(), makeStatusBar())

    assert.strictEqual(calls.length, 1)
    assert.deepStrictEqual(calls[0], { forceRefreshRules: true })
  })

  it('updates status bar to scanning then done on success', async () => {
    const client = makeClient({ scanScope: async () => makeFindings(1) })
    const statusBar = makeStatusBar()

    await rescanLatest(client, makeDiagnosticCollection(), makeTree(), statusBar)

    assert.ok(statusBar._states.includes('scanning'), 'should enter scanning state')
    assert.ok(statusBar._states.includes('done'), 'should enter done state')
  })

  it('updates status bar to error on failure', async () => {
    const client = makeClient({
      scanScope: async () => { throw new Error('network error') },
    })
    const statusBar = makeStatusBar()

    await rescanLatest(client, makeDiagnosticCollection(), makeTree(), statusBar)

    assert.ok(statusBar._states.includes('error'), 'should enter error state on failure')
  })

  it('returns findings on success', async () => {
    const findings = makeFindings(4)
    const client = makeClient({ scanScope: async () => findings })

    const result = await rescanLatest(client, makeDiagnosticCollection(), makeTree(), makeStatusBar())

    assert.deepStrictEqual(result, findings)
  })

  it('returns undefined on failure', async () => {
    const client = makeClient({
      scanScope: async () => { throw new Error('oops') },
    })

    const result = await rescanLatest(client, makeDiagnosticCollection(), makeTree(), makeStatusBar())

    assert.strictEqual(result, undefined)
  })

  it('shows error when no workspace folder open', async () => {
    const errors: string[] = []
    vscodeMock.window.showErrorMessage = (msg: string) => { errors.push(msg); return Promise.resolve(undefined) }

    const savedFolders = vscodeMock.workspace.workspaceFolders
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(vscodeMock.workspace as any).workspaceFolders = undefined

    const client = makeClient()
    const result = await rescanLatest(client, makeDiagnosticCollection(), makeTree(), makeStatusBar())

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(vscodeMock.workspace as any).workspaceFolders = savedFolders

    assert.strictEqual(result, undefined)
    assert.ok(errors.some((m: string) => m.includes('No workspace folder')))
  })
})

// ── AegisClient.scanScope (arg-building logic) ────────────────────────────────

describe('AegisClient.scanScope()', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { AegisClient } = require('../src/client')

  it('constructs correctly with minimal config', () => {
    const config = { cliPath: 'aegis', baseUrl: '', apiToken: '', org: '', scanOnSave: false }
    const client = new AegisClient(config)
    assert.ok(typeof client.scanScope === 'function')
  })
})

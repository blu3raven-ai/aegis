/**
 * Unit tests for pure functions in the Aegis VSCode extension.
 *
 * Full electron-based integration tests (via @vscode/test-electron) require
 * a live VS Code instance and are intentionally out of scope for v1 CI.
 * These tests cover the logic that does not depend on the VSCode runtime by
 * using a minimal mock of the vscode module.
 *
 * TODO: Add full integration tests with @vscode/test-electron once a
 * headless CI environment is available.
 */

import assert from 'assert'
// Must be first so the vscode mock is in place before any extension source loads.
import './setup'

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { severityToVscode, applyDiagnostics } = require('../src/diagnostics')
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { AegisClient } = require('../src/client')

describe('severityToVscode()', () => {
  it('maps critical to Error', () => {
    assert.strictEqual(severityToVscode('critical'), 0)
  })

  it('maps high to Error', () => {
    assert.strictEqual(severityToVscode('high'), 0)
  })

  it('maps medium to Warning', () => {
    assert.strictEqual(severityToVscode('medium'), 1)
  })

  it('maps low to Information', () => {
    assert.strictEqual(severityToVscode('low'), 2)
  })
})

describe('applyDiagnostics()', () => {
  it('groups findings by file', () => {
    const findings = [
      { id: '1', filePath: 'src/foo.py', line: 10, severity: 'high', ruleId: 'R001', message: 'msg 1', scanner: 'sast' },
      { id: '2', filePath: 'src/foo.py', line: 20, severity: 'medium', ruleId: 'R002', message: 'msg 2', scanner: 'sast' },
      { id: '3', filePath: 'src/bar.py', line: 5, severity: 'low', ruleId: 'R003', message: 'msg 3', scanner: 'secrets' },
    ]
    const setArgs: Array<[unknown, unknown[]]> = []
    const collection = { clear: () => {}, set: (uri: unknown, diags: unknown[]) => setArgs.push([uri, diags]) }
    applyDiagnostics(collection, findings, '/workspace')
    assert.strictEqual(setArgs.length, 2)
    assert.ok(setArgs.find(([, d]) => d.length === 2), 'foo.py should have 2 diagnostics')
    assert.ok(setArgs.find(([, d]) => d.length === 1), 'bar.py should have 1 diagnostic')
  })

  it('assigns Error severity for critical findings', () => {
    const findings = [{ id: '1', filePath: 'src/vuln.py', line: 1, severity: 'critical', ruleId: 'R001', message: 'critical issue', scanner: 'sast' }]
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let capturedDiags: any[] = []
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const collection = { clear: () => {}, set: (_uri: unknown, diags: any[]) => { capturedDiags = diags } }
    applyDiagnostics(collection, findings, '/workspace')
    assert.strictEqual(capturedDiags[0].severity, 0)
  })

  it('includes scanner name and severity in the diagnostic source', () => {
    const findings = [{ id: '1', filePath: 'src/vuln.py', line: 1, severity: 'medium', ruleId: 'R001', message: 'issue', scanner: 'secrets' }]
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let capturedDiags: any[] = []
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const collection = { clear: () => {}, set: (_uri: unknown, diags: any[]) => { capturedDiags = diags } }
    applyDiagnostics(collection, findings, '/workspace')
    assert.ok(capturedDiags[0].source?.includes('secrets'))
    assert.ok(capturedDiags[0].source?.includes('medium'))
  })

  it('always clears existing diagnostics before applying new ones', () => {
    let cleared = false
    const collection = { clear: () => { cleared = true }, set: () => {} }
    applyDiagnostics(collection, [], '/workspace')
    assert.ok(cleared)
  })

  it('handles empty findings list without calling set()', () => {
    const collection = { clear: () => {}, set: () => { throw new Error('set() should not be called') } }
    assert.doesNotThrow(() => applyDiagnostics(collection, [], '/workspace'))
  })
})

describe('AegisClient', () => {
  it('constructs without throwing given a valid config object', () => {
    const config = { cliPath: 'aegis', baseUrl: 'https://aegis.example.org', apiToken: 'tok-abc123', org: 'example-org', scanOnSave: false }
    assert.doesNotThrow(() => new AegisClient(config))
  })

  it('constructs with empty optional fields', () => {
    const config = { cliPath: 'aegis', baseUrl: '', apiToken: '', org: '', scanOnSave: false }
    assert.doesNotThrow(() => new AegisClient(config))
  })
})

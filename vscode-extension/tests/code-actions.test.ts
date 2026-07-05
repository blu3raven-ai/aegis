/**
 * Tests for AegisCodeActionProvider.
 *
 * Exercises the quick-fix action generation logic using mock diagnostics and
 * findings, without requiring a live VSCode instance.
 */
import assert from 'assert'
// Must be first so the vscode mock is in place before any extension source loads.
import './setup'

// ── Import under test ─────────────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { AegisCodeActionProvider } = require('../src/codeActions')

// ── Helper ────────────────────────────────────────────────────────────────────

function makeFinding(overrides = {}) {
  return {
    id: 'finding-1',
    filePath: '/workspace/src/foo.py',
    line: 10,
    severity: 'high',
    ruleId: 'R001',
    message: 'SQL injection',
    scanner: 'sast',
    ...overrides,
  }
}

function makeDiagnostic(line = 9, ruleId = 'R001') {
  return {
    source: 'aegis/sast [high]',
    code: ruleId,
    range: { start: { line }, end: { line } },
    message: 'SQL injection',
    severity: 0,
  }
}

function makeDocument(fsPath = '/workspace/src/foo.py') {
  return { uri: { fsPath } }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('AegisCodeActionProvider', () => {
  it('returns no actions when no aegis diagnostics are present', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([makeFinding()])

    const context = { diagnostics: [{ source: 'eslint', code: 'no-unused-vars' }] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)
    assert.strictEqual(actions.length, 0)
  })

  it('returns actions for a matching aegis diagnostic', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([makeFinding()])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)
    assert.ok(actions.length > 0, 'Expected at least one action')
  })

  it('includes "show finding details" action', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([makeFinding()])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detailAction = actions.find((a: any) => a.command?.command === 'aegis.showFindingDetails')
    assert.ok(detailAction, 'Expected aegis.showFindingDetails action')
  })

  it('includes "snooze" action', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([makeFinding()])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const snoozeAction = actions.find((a: any) => a.command?.command === 'aegis.snoozeFinding')
    assert.ok(snoozeAction, 'Expected aegis.snoozeFinding action')
  })

  it('includes "mark fixed" action', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([makeFinding()])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const fixAction = actions.find((a: any) => a.command?.command === 'aegis.markFixed')
    assert.ok(fixAction, 'Expected aegis.markFixed action')
  })

  it('includes "show chain" action only when finding has chainId', () => {
    const provider = new AegisCodeActionProvider()
    const finding = makeFinding({ chainId: 'chain-123' })
    provider.update([finding])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const chainAction = actions.find((a: any) => a.command?.command === 'aegis.showChain')
    assert.ok(chainAction, 'Expected aegis.showChain action for finding with chainId')
  })

  it('omits "show chain" action when finding has no chainId', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([makeFinding()])  // no chainId

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const chainAction = actions.find((a: any) => a.command?.command === 'aegis.showChain')
    assert.ok(!chainAction, 'Should not produce showChain action for finding without chainId')
  })

  it('passes finding ID and duration to snooze command arguments', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([makeFinding({ id: 'finding-xyz' })])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const snoozeAction = actions.find((a: any) => a.command?.command === 'aegis.snoozeFinding')
    assert.ok(snoozeAction, 'Expected snooze action')
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const args = (snoozeAction as any).command.arguments
    assert.strictEqual(args[0], 'finding-xyz', 'First arg must be findingId')
    assert.strictEqual(args[1], 7, 'Second arg must be 7 days')
  })

  it('passes finding object to showFindingDetails command', () => {
    const finding = makeFinding({ id: 'finding-abc' })
    const provider = new AegisCodeActionProvider()
    provider.update([finding])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detailAction = actions.find((a: any) => a.command?.command === 'aegis.showFindingDetails')
    assert.ok(detailAction)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const args = (detailAction as any).command.arguments
    assert.deepStrictEqual(args[0], finding)
  })

  it('returns empty actions for empty findings list', () => {
    const provider = new AegisCodeActionProvider()
    provider.update([])

    const context = { diagnostics: [makeDiagnostic(9, 'R001')] }
    const actions = provider.provideCodeActions(makeDocument(), null, context)
    assert.strictEqual(actions.length, 0)
  })
})

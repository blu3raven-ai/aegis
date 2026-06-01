/**
 * Tests for the updated FindingsTreeProvider grouping logic.
 *
 * Verifies the Severity → Scanner → File → Finding hierarchy without
 * requiring a live VSCode instance.
 */
import assert from 'assert'
// Must be first so the vscode mock is in place before any extension source loads.
import './setup'

// ── Import under test ─────────────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-require-imports
const {
  FindingsTreeProvider,
  SeverityGroupNode,
  ScannerGroupNode,
  FileGroupNode,
  FindingNode,
} = require('../src/findingsTreeProvider')

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeFindings() {
  return [
    { id: '1', filePath: '/ws/src/auth.py',  line: 5,  severity: 'critical', ruleId: 'SQL001', message: 'SQLi', scanner: 'sast' },
    { id: '2', filePath: '/ws/src/auth.py',  line: 12, severity: 'critical', ruleId: 'SQL001', message: 'SQLi 2', scanner: 'sast' },
    { id: '3', filePath: '/ws/src/util.py',  line: 3,  severity: 'high',     ruleId: 'XSS001', message: 'XSS', scanner: 'sast' },
    { id: '4', filePath: '/ws/src/util.py',  line: 8,  severity: 'high',     ruleId: 'SEC002', message: 'Hardcoded secret', scanner: 'secrets' },
    { id: '5', filePath: '/ws/src/api.py',   line: 20, severity: 'medium',   ruleId: 'DEP001', message: 'Outdated dep', scanner: 'sca' },
    { id: '6', filePath: '/ws/src/api.py',   line: 30, severity: 'low',      ruleId: 'STYLE1', message: 'Code smell', scanner: 'sast' },
  ]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('FindingsTreeProvider grouping', () => {
  it('root children are SeverityGroupNodes', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const roots = provider.getChildren()
    assert.ok(roots.length > 0, 'Expected non-empty root')
    for (const root of roots) {
      assert.ok(
        root instanceof SeverityGroupNode,
        `Expected SeverityGroupNode, got ${root?.constructor?.name}`,
      )
    }
  })

  it('severity groups appear in critical → high → medium → low order', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const roots = provider.getChildren()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const severities = roots.map((n: any) => n.severity)
    assert.deepStrictEqual(severities, ['critical', 'high', 'medium', 'low'])
  })

  it('severity group label includes count', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const roots = provider.getChildren()
    const criticalNode = roots[0]
    assert.ok(
      (criticalNode.label as string).includes('2'),
      'Critical group label should contain count 2',
    )
  })

  it('children of severity group are ScannerGroupNodes', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const [criticalNode] = provider.getChildren()
    const scanners = provider.getChildren(criticalNode)
    assert.ok(scanners.length > 0)
    for (const s of scanners) {
      assert.ok(
        s instanceof ScannerGroupNode,
        `Expected ScannerGroupNode, got ${s?.constructor?.name}`,
      )
    }
  })

  it('children of scanner group are FileGroupNodes', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const [criticalNode] = provider.getChildren()
    const [scannerNode] = provider.getChildren(criticalNode)
    const files = provider.getChildren(scannerNode)
    assert.ok(files.length > 0)
    for (const f of files) {
      assert.ok(
        f instanceof FileGroupNode,
        `Expected FileGroupNode, got ${f?.constructor?.name}`,
      )
    }
  })

  it('children of file group are FindingNodes', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const [criticalNode] = provider.getChildren()
    const [scannerNode] = provider.getChildren(criticalNode)
    const [fileNode] = provider.getChildren(scannerNode)
    const findings = provider.getChildren(fileNode)
    assert.ok(findings.length > 0)
    for (const f of findings) {
      assert.ok(
        f instanceof FindingNode,
        `Expected FindingNode, got ${f?.constructor?.name}`,
      )
    }
  })

  it('findings within a file are sorted by line number', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const [criticalNode] = provider.getChildren()
    const [scannerNode] = provider.getChildren(criticalNode)
    const [fileNode] = provider.getChildren(scannerNode)
    const findingNodes = provider.getChildren(fileNode)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const lines: number[] = findingNodes.map((n: any) => n.finding.line)
    for (let i = 1; i < lines.length; i++) {
      assert.ok(lines[i] >= lines[i - 1], `Lines should be sorted: ${lines}`)
    }
  })

  it('high severity group contains two scanners for the fixture data', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const roots = provider.getChildren()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const highNode = roots.find((n: any) => n.severity === 'high')
    assert.ok(highNode, 'Expected a high severity group')
    const scanners = provider.getChildren(highNode)
    assert.strictEqual(scanners.length, 2, 'high group should have 2 scanners (sast + secrets)')
  })

  it('clear() empties the tree', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())
    provider.clear()

    const roots = provider.getChildren()
    assert.strictEqual(roots.length, 0, 'Tree should be empty after clear()')
  })

  it('empty findings produce no root nodes', () => {
    const provider = new FindingsTreeProvider()
    provider.update([])

    const roots = provider.getChildren()
    assert.strictEqual(roots.length, 0)
  })

  it('FindingNode has a command for navigation', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const [criticalNode] = provider.getChildren()
    const [scannerNode] = provider.getChildren(criticalNode)
    const [fileNode] = provider.getChildren(scannerNode)
    const [findingNode] = provider.getChildren(fileNode)

    assert.ok(findingNode.command, 'FindingNode must have a navigation command')
    assert.strictEqual(findingNode.command.command, 'vscode.open')
  })

  it('scanner group label includes count', () => {
    const provider = new FindingsTreeProvider()
    provider.update(makeFindings())

    const [criticalNode] = provider.getChildren()
    const [scannerNode] = provider.getChildren(criticalNode)
    assert.ok(
      (scannerNode.label as string).includes('2'),
      'Scanner group for sast under critical should show count 2',
    )
  })
})

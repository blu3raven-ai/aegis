import assert from 'assert'
import './setup'

// eslint-disable-next-line @typescript-eslint/no-require-imports
const {
  LiveFindingsTreeProvider,
  LiveSeverityGroupNode,
  LiveFindingNode,
  MAX_LIVE_ITEMS,
} = require('../src/live/liveFindingsTreeProvider')

function event(overrides: Record<string, unknown> = {}) {
  return {
    event_type: 'finding.created',
    finding_id: `f-${Math.random().toString(36).slice(2, 8)}`,
    severity: 'high',
    scanner_type: 'sast',
    file_path: '/ws/src/x.py',
    line: 10,
    title: 'Issue',
    payload: {},
    ...overrides,
  }
}

describe('LiveFindingsTreeProvider', () => {
  it('starts empty', () => {
    const p = new LiveFindingsTreeProvider()
    assert.strictEqual(p.size(), 0)
    assert.deepStrictEqual(p.getChildren(), [])
  })

  it('groups by severity in critical→high→medium→low order', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ severity: 'low' }))
    p.add(event({ severity: 'critical' }))
    p.add(event({ severity: 'medium' }))
    p.add(event({ severity: 'high' }))

    const roots = p.getChildren()
    assert.strictEqual(roots.length, 4)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assert.deepStrictEqual(roots.map((r: any) => r.severity), ['critical', 'high', 'medium', 'low'])
    for (const r of roots) assert.ok(r instanceof LiveSeverityGroupNode)
  })

  it('omits empty severities entirely', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ severity: 'high' }))
    p.add(event({ severity: 'low' }))
    const roots = p.getChildren()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assert.deepStrictEqual(roots.map((r: any) => r.severity), ['high', 'low'])
  })

  it('caps at MAX_LIVE_ITEMS with FIFO eviction', () => {
    const p = new LiveFindingsTreeProvider()
    for (let i = 0; i < MAX_LIVE_ITEMS + 5; i++) {
      p.add(event({ finding_id: `f${i}`, severity: 'medium' }))
    }
    assert.strictEqual(p.size(), MAX_LIVE_ITEMS)
    const snap = p.snapshot()
    assert.strictEqual(snap[0].finding_id, 'f5')
    assert.strictEqual(snap[snap.length - 1].finding_id, `f${MAX_LIVE_ITEMS + 4}`)
  })

  it('replaces an existing entry when the same finding_id arrives again', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ finding_id: 'same', severity: 'high', title: 'v1' }))
    p.add(event({ finding_id: 'other', severity: 'low' }))
    p.add(event({ finding_id: 'same', severity: 'high', title: 'v2' }))
    assert.strictEqual(p.size(), 2)
    const leaves = p.getChildren(new LiveSeverityGroupNode('high', 1))
    assert.strictEqual(leaves.length, 1)
    assert.strictEqual(leaves[0].entry.title, 'v2')
  })

  it('keeps duplicates separate when finding_id is absent', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ finding_id: undefined, severity: 'medium', title: 'a' }))
    p.add(event({ finding_id: undefined, severity: 'medium', title: 'b' }))
    assert.strictEqual(p.size(), 2)
  })

  it('leaves are LiveFindingNodes showing newest-first within a severity', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ finding_id: 'A', severity: 'high', title: 'older' }))
    p.add(event({ finding_id: 'B', severity: 'high', title: 'newer' }))
    const group = p.getChildren()[0]
    const leaves = p.getChildren(group)
    assert.strictEqual(leaves.length, 2)
    for (const l of leaves) assert.ok(l instanceof LiveFindingNode)
    assert.strictEqual(leaves[0].entry.title, 'newer')
    assert.strictEqual(leaves[1].entry.title, 'older')
  })

  it('LiveFindingNode wires a vscode.open command to the right line', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ file_path: '/ws/src/y.py', line: 42, severity: 'critical' }))
    const group = p.getChildren()[0]
    const leaf = p.getChildren(group)[0]
    assert.ok(leaf.command)
    assert.strictEqual(leaf.command.command, 'vscode.open')
    const [, opts] = leaf.command.arguments
    assert.strictEqual(opts.selection.start.line, 41)
  })

  it('leaf description includes scanner and file:line', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ scanner_type: 'secrets', file_path: '/ws/src/api.py', line: 9 }))
    const group = p.getChildren()[0]
    const leaf = p.getChildren(group)[0]
    assert.ok(leaf.description.includes('secrets'))
    assert.ok(leaf.description.includes('api.py:9'))
  })

  it('clear() empties the tree', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event())
    p.add(event())
    p.clear()
    assert.strictEqual(p.size(), 0)
    assert.deepStrictEqual(p.getChildren(), [])
  })

  it('unknown severity groups under "unknown"', () => {
    const p = new LiveFindingsTreeProvider()
    p.add(event({ severity: 'something-else' }))
    const roots = p.getChildren()
    assert.strictEqual(roots.length, 1)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assert.strictEqual((roots[0] as any).severity, 'unknown')
  })
})

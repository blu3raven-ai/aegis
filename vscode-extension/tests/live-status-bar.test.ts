import assert from 'assert'
import './setup'

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { formatLiveStatus, LiveStatusBar } = require('../src/live/liveStatusBar')

describe('formatLiveStatus()', () => {
  it('connected, zero count: filled dot, no suffix', () => {
    assert.strictEqual(formatLiveStatus('connected', 0), '● Aegis Live')
  })

  it('connected, non-zero count: filled dot with (N) suffix', () => {
    assert.strictEqual(formatLiveStatus('connected', 7), '● Aegis Live (7)')
  })

  it('disconnected, zero count: hollow dot, no suffix', () => {
    assert.strictEqual(formatLiveStatus('disconnected', 0), '○ Aegis Live')
  })

  it('disconnected, non-zero count: hollow dot with (N) suffix', () => {
    assert.strictEqual(formatLiveStatus('disconnected', 3), '○ Aegis Live (3)')
  })
})

describe('LiveStatusBar', () => {
  it('starts disconnected with empty count', () => {
    const sb = new LiveStatusBar()
    assert.strictEqual(sb.text(), '○ Aegis Live')
    sb.dispose()
  })

  it('flips to connected text on setState("connected")', () => {
    const sb = new LiveStatusBar()
    sb.setState('connected')
    assert.strictEqual(sb.text(), '● Aegis Live')
    sb.dispose()
  })

  it('reflects count updates while connected', () => {
    const sb = new LiveStatusBar()
    sb.setState('connected')
    sb.setCount(5)
    assert.strictEqual(sb.text(), '● Aegis Live (5)')
    sb.setCount(0)
    assert.strictEqual(sb.text(), '● Aegis Live')
    sb.dispose()
  })

  it('clamps negative counts to zero', () => {
    const sb = new LiveStatusBar()
    sb.setState('connected')
    sb.setCount(-2)
    assert.strictEqual(sb.text(), '● Aegis Live')
    sb.dispose()
  })

  it('returning to disconnected keeps the existing count', () => {
    const sb = new LiveStatusBar()
    sb.setState('connected')
    sb.setCount(4)
    sb.setState('disconnected')
    assert.strictEqual(sb.text(), '○ Aegis Live (4)')
    sb.dispose()
  })
})

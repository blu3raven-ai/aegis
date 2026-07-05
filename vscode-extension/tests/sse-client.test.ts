/**
 * Unit tests for the SSE client: pure parsing + projection.  The HTTP
 * transport itself is exercised manually with a running backend (out of
 * scope for unit tests per the project pattern).
 */
import assert from 'assert'
import './setup'

// eslint-disable-next-line @typescript-eslint/no-require-imports
const {
  parseSseBlock,
  SseStreamParser,
  unwrapPayload,
  isFindingEvent,
  toFindingEvent,
  FINDING_EVENT_TYPES,
} = require('../src/live/sseClient')

describe('parseSseBlock()', () => {
  it('parses a single event with id, event, and data', () => {
    const block = 'id:42\nevent:finding.created\ndata:{"finding_id":"f1"}'
    const ev = parseSseBlock(block)
    assert.deepStrictEqual(ev, { id: '42', event: 'finding.created', data: { finding_id: 'f1' } })
  })

  it('strips a single leading space after the colon', () => {
    const block = 'event: finding.closed\ndata: {"finding_id":"f9"}'
    const ev = parseSseBlock(block)
    assert.strictEqual(ev.event, 'finding.closed')
    assert.deepStrictEqual(ev.data, { finding_id: 'f9' })
  })

  it('returns null for heartbeat-only blocks', () => {
    assert.strictEqual(parseSseBlock(':heartbeat 123'), null)
  })

  it('returns null when JSON in data is malformed', () => {
    const block = 'event:finding.created\ndata:{not-json'
    assert.strictEqual(parseSseBlock(block), null)
  })

  it('returns null when event field is missing', () => {
    const block = 'id:7\ndata:{"x":1}'
    assert.strictEqual(parseSseBlock(block), null)
  })

  it('joins multiple data lines with newlines before JSON parse', () => {
    const block = 'event:finding.created\ndata:{"a":1,\ndata:"b":2}'
    const ev = parseSseBlock(block)
    assert.deepStrictEqual(ev.data, { a: 1, b: 2 })
  })
})

describe('SseStreamParser', () => {
  it('emits events as complete blocks arrive', () => {
    const p = new SseStreamParser()
    const out = p.feed(
      'event:finding.created\ndata:{"finding_id":"f1"}\n\n' +
      'event:finding.closed\ndata:{"finding_id":"f2"}\n\n',
    )
    assert.strictEqual(out.length, 2)
    assert.strictEqual(out[0].event, 'finding.created')
    assert.strictEqual(out[1].event, 'finding.closed')
  })

  it('buffers across chunks split mid-block', () => {
    const p = new SseStreamParser()
    assert.strictEqual(p.feed('event:finding.created\nda').length, 0)
    const out = p.feed('ta:{"finding_id":"fX"}\n\n')
    assert.strictEqual(out.length, 1)
    assert.strictEqual(out[0].data.finding_id, 'fX')
  })

  it('handles CRLF block separators', () => {
    const p = new SseStreamParser()
    const out = p.feed('event:finding.created\r\ndata:{"finding_id":"crlf"}\r\n\r\n')
    assert.strictEqual(out.length, 1)
    assert.strictEqual(out[0].data.finding_id, 'crlf')
  })

  it('skips malformed blocks without breaking the stream', () => {
    const p = new SseStreamParser()
    const out = p.feed(
      'event:finding.created\ndata:not-json\n\n' +
      'event:finding.closed\ndata:{"finding_id":"ok"}\n\n',
    )
    assert.strictEqual(out.length, 1)
    assert.strictEqual(out[0].event, 'finding.closed')
  })

  it('skips heartbeat blocks', () => {
    const p = new SseStreamParser()
    const out = p.feed(
      ':heartbeat 1\n\n' +
      'event:finding.created\ndata:{"finding_id":"f1"}\n\n',
    )
    assert.strictEqual(out.length, 1)
    assert.strictEqual(out[0].event, 'finding.created')
  })
})

describe('unwrapPayload()', () => {
  it('unwraps {event_id, payload} envelope', () => {
    assert.deepStrictEqual(
      unwrapPayload({ event_id: 1, payload: { finding_id: 'x' } }),
      { finding_id: 'x' },
    )
  })

  it('returns the object directly when no payload key', () => {
    assert.deepStrictEqual(unwrapPayload({ finding_id: 'x' }), { finding_id: 'x' })
  })

  it('returns empty object for non-object input', () => {
    assert.deepStrictEqual(unwrapPayload(null), {})
    assert.deepStrictEqual(unwrapPayload('string'), {})
  })
})

describe('isFindingEvent()', () => {
  for (const t of FINDING_EVENT_TYPES) {
    it(`accepts ${t}`, () => {
      assert.strictEqual(isFindingEvent({ event: t, data: {} }), true)
    })
  }

  it('rejects unrelated event types', () => {
    assert.strictEqual(isFindingEvent({ event: 'scan.started', data: {} }), false)
    assert.strictEqual(isFindingEvent({ event: '', data: {} }), false)
  })
})

describe('toFindingEvent()', () => {
  it('projects a wrapped finding.created event', () => {
    const ev = toFindingEvent({
      id: '7',
      event: 'finding.created',
      data: {
        event_id: 7,
        payload: {
          finding_id: 'f1',
          severity: 'critical',
          scanner_type: 'sast',
          file_path: 'src/foo.py',
          line: 12,
          title: 'SQL injection',
        },
      },
    })
    assert.strictEqual(ev.event_type, 'finding.created')
    assert.strictEqual(ev.finding_id, 'f1')
    assert.strictEqual(ev.severity, 'critical')
    assert.strictEqual(ev.scanner_type, 'sast')
    assert.strictEqual(ev.file_path, 'src/foo.py')
    assert.strictEqual(ev.line, 12)
    assert.strictEqual(ev.title, 'SQL injection')
  })

  it('also handles an unwrapped payload', () => {
    const ev = toFindingEvent({
      event: 'finding.closed',
      data: { finding_id: 'fZ', severity: 'low', scanner: 'secrets' },
    })
    assert.strictEqual(ev.event_type, 'finding.closed')
    assert.strictEqual(ev.finding_id, 'fZ')
    assert.strictEqual(ev.scanner_type, 'secrets')
  })

  it('returns null for non-finding event types', () => {
    assert.strictEqual(
      toFindingEvent({ event: 'scan.started', data: {} }),
      null,
    )
  })

  it('leaves missing fields undefined rather than empty strings', () => {
    const ev = toFindingEvent({ event: 'finding.merged', data: {} })
    assert.strictEqual(ev.finding_id, undefined)
    assert.strictEqual(ev.severity, undefined)
    assert.strictEqual(ev.line, undefined)
  })
})

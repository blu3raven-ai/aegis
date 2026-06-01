/**
 * Minimal SSE client for the Aegis backend event stream.
 *
 * Mirrors the wire-level behaviour of the `aegis watch` CLI: subscribes to
 * `GET /events/api/stream`, parses `id:`/`event:`/`data:` blocks, filters
 * to the four finding-related event types, and surfaces each parsed event
 * via a callback.  No reconnect loop — the user re-runs the command.
 */
import * as http from 'http'
import * as https from 'https'
import { URL } from 'url'

/** Event types the live findings view cares about. */
export const FINDING_EVENT_TYPES = [
  'finding.created',
  'finding.severity_changed',
  'finding.merged',
  'finding.closed',
] as const

export type FindingEventType = (typeof FINDING_EVENT_TYPES)[number]

export interface SseEvent {
  id?: string
  event: string
  data: unknown
}

export interface FindingEvent {
  event_type: FindingEventType
  event_id?: string
  finding_id?: string
  severity?: string
  scanner_type?: string
  file_path?: string
  line?: number
  title?: string
  payload: Record<string, unknown>
}

/**
 * Parse a single SSE block (id/event/data lines separated by `\n`, blocks by
 * `\n\n`).  Returns null for comments (`:heartbeat ...`) or malformed input.
 *
 * Exported for unit testing — the streamer below feeds raw chunks into this.
 */
export function parseSseBlock(block: string): SseEvent | null {
  const lines = block.split(/\r?\n/)
  let id: string | undefined
  let event: string | undefined
  const dataLines: string[] = []
  let sawField = false

  for (const raw of lines) {
    if (raw.startsWith(':') || raw.length === 0) continue
    const colon = raw.indexOf(':')
    if (colon === -1) continue
    const field = raw.slice(0, colon)
    let value = raw.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)

    if (field === 'id') {
      id = value
      sawField = true
    } else if (field === 'event') {
      event = value
      sawField = true
    } else if (field === 'data') {
      dataLines.push(value)
      sawField = true
    }
  }

  if (!sawField || !event || dataLines.length === 0) return null

  const raw = dataLines.join('\n')
  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return null
  }

  return { id, event, data }
}

/**
 * Stateful chunk parser — buffers across network reads and emits one event
 * per complete `\n\n`-delimited block.
 */
export class SseStreamParser {
  private buffer = ''

  feed(chunk: string): SseEvent[] {
    this.buffer += chunk
    const events: SseEvent[] = []
    let idx: number
    while ((idx = findBlockEnd(this.buffer)) !== -1) {
      const block = this.buffer.slice(0, idx)
      this.buffer = this.buffer.slice(idx + blockSepLength(this.buffer, idx))
      const parsed = parseSseBlock(block)
      if (parsed) events.push(parsed)
    }
    return events
  }
}

function findBlockEnd(buf: string): number {
  const lf = buf.indexOf('\n\n')
  const crlf = buf.indexOf('\r\n\r\n')
  if (lf === -1) return crlf
  if (crlf === -1) return lf
  return Math.min(lf, crlf)
}

function blockSepLength(buf: string, idx: number): number {
  return buf.startsWith('\r\n\r\n', idx) ? 4 : 2
}

/**
 * Unwrap the bus envelope.  The Phase 0 bus wraps payloads as
 * `{event_id, payload}` for some event types; older publishers send the
 * payload directly.  Returns the inner finding-shaped object either way.
 */
export function unwrapPayload(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== 'object') return {}
  const obj = data as Record<string, unknown>
  if (
    'payload' in obj &&
    obj.payload &&
    typeof obj.payload === 'object'
  ) {
    return obj.payload as Record<string, unknown>
  }
  return obj
}

/** Returns true iff event.event is one of the four finding event types. */
export function isFindingEvent(event: SseEvent): boolean {
  return (FINDING_EVENT_TYPES as readonly string[]).includes(event.event)
}

/**
 * Project an SSE event into the FindingEvent shape used by the UI.  Pulls
 * fields from either the wrapped or unwrapped payload to stay compatible
 * with both bus formats.
 */
export function toFindingEvent(event: SseEvent): FindingEvent | null {
  if (!isFindingEvent(event)) return null
  const payload = unwrapPayload(event.data)
  return {
    event_type: event.event as FindingEventType,
    event_id: event.id,
    finding_id: stringOrUndefined(payload.finding_id ?? payload.id),
    severity: stringOrUndefined(payload.severity),
    scanner_type: stringOrUndefined(payload.scanner_type ?? payload.scanner),
    file_path: stringOrUndefined(payload.file_path ?? payload.filePath),
    line: numberOrUndefined(payload.line),
    title: stringOrUndefined(payload.title ?? payload.message),
    payload,
  }
}

function stringOrUndefined(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined
}

function numberOrUndefined(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

export interface SseClientOptions {
  baseUrl: string
  apiToken?: string
  /** Called once per finding event after filtering + projection. */
  onEvent: (event: FindingEvent) => void
  /** Connection opened (after HTTP headers received with 2xx). */
  onOpen?: () => void
  /** Stream closed cleanly. */
  onClose?: () => void
  /** Connection or HTTP error. */
  onError?: (err: Error) => void
}

export interface SseConnection {
  /** Close the connection.  Idempotent. */
  close(): void
}

/**
 * Open the SSE stream and dispatch finding events through callbacks.
 *
 * Returns synchronously with a handle whose `close()` aborts the request.
 * All errors (network, HTTP non-2xx, malformed) surface through `onError`.
 */
export function connectSse(opts: SseClientOptions): SseConnection {
  const url = new URL('/events/api/stream', opts.baseUrl)
  const lib = url.protocol === 'https:' ? https : http

  const headers: Record<string, string> = { Accept: 'text/event-stream' }
  if (opts.apiToken) headers.Authorization = `Bearer ${opts.apiToken}`

  let closed = false
  const parser = new SseStreamParser()

  const req = lib.request(
    {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'GET',
      headers,
    },
    (res) => {
      if (closed) {
        res.destroy()
        return
      }
      const status = res.statusCode ?? 0
      if (status < 200 || status >= 300) {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (c) => { body += c })
        res.on('end', () => {
          opts.onError?.(new Error(
            `Aegis SSE stream returned HTTP ${status}: ${body.slice(0, 200).trim()}`,
          ))
        })
        return
      }

      res.setEncoding('utf8')
      opts.onOpen?.()

      res.on('data', (chunk: string) => {
        if (closed) return
        for (const ev of parser.feed(chunk)) {
          const finding = toFindingEvent(ev)
          if (finding) {
            try {
              opts.onEvent(finding)
            } catch (err) {
              opts.onError?.(err as Error)
            }
          }
        }
      })

      res.on('end', () => {
        if (!closed) opts.onClose?.()
      })

      res.on('error', (err) => {
        if (!closed) opts.onError?.(err)
      })
    },
  )

  req.on('error', (err) => {
    if (!closed) opts.onError?.(err)
  })

  req.end()

  return {
    close() {
      if (closed) return
      closed = true
      req.destroy()
    },
  }
}

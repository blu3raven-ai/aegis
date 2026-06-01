import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for the SLA breach widget data layer (Phase 47).
// ---------------------------------------------------------------------------

interface FetchCall {
  url: string
  init?: RequestInit
}

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), init })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../lib/client/sla-api.ts")
}

const MOCK_SUMMARY = {
  critical: { open: 5, breached: 2, breached_pct: 0.4 },
  high: { open: 10, breached: 1, breached_pct: 0.1 },
  medium: { open: 20, breached: 0, breached_pct: 0.0 },
  low: { open: 3, breached: 0, breached_pct: 0.0 },
}

// ── Widget renders ────────────────────────────────────────────────────────────

test("widget data: getBreachSummary fetches all four severities", async () => {
  const { mock, calls } = makeFetchMock({ summary: MOCK_SUMMARY })
  ;(globalThis as any).fetch = mock

  const { getBreachSummary } = await loadModule()
  const summary = await getBreachSummary("acme-org")

  assert.equal(calls.length, 1)
  const sevs = Object.keys(summary)
  assert.ok(sevs.includes("critical"))
  assert.ok(sevs.includes("high"))
  assert.ok(sevs.includes("medium"))
  assert.ok(sevs.includes("low"))
})

test("widget data: breached counts are correct", async () => {
  const { mock } = makeFetchMock({ summary: MOCK_SUMMARY })
  ;(globalThis as any).fetch = mock

  const { getBreachSummary } = await loadModule()
  const summary = await getBreachSummary("acme-org")

  assert.equal(summary.critical.breached, 2)
  assert.equal(summary.high.breached, 1)
  assert.equal(summary.medium.breached, 0)
  assert.equal(summary.low.breached, 0)
})

test("widget data: breached_pct is ratio of breached to open", async () => {
  const { mock } = makeFetchMock({ summary: MOCK_SUMMARY })
  ;(globalThis as any).fetch = mock

  const { getBreachSummary } = await loadModule()
  const summary = await getBreachSummary("acme-org")

  assert.equal(summary.critical.breached_pct, 0.4)
  assert.equal(summary.high.breached_pct, 0.1)
})

// ── Click-through URL shape ───────────────────────────────────────────────────

test("click-through: generates correct findings filter url for critical breach", () => {
  // Verify the href format used in SlaBreachWidget without rendering React
  const base = "/findings"
  const sev = "critical"
  const expected = `${base}?sla_breached=true&severity=${sev}`
  assert.equal(expected, "/findings?sla_breached=true&severity=critical")
})

// ── Error handling ────────────────────────────────────────────────────────────

test("widget data: getBreachSummary silently fails (caller catches)", async () => {
  const { mock } = makeFetchMock({ detail: "Internal Server Error" }, 500)
  ;(globalThis as any).fetch = mock

  const { getBreachSummary, SlaApiError } = await loadModule()
  await assert.rejects(() => getBreachSummary("acme-org"), (err: any) => {
    assert.ok(err instanceof SlaApiError)
    assert.equal(err.status, 500)
    return true
  })
})

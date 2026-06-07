import test, { beforeEach } from "node:test"
import assert from "node:assert/strict"

// apiClient requires a CSRF cookie for POST/PUT/DELETE requests
beforeEach(() => {
  ;(globalThis as any).document = { cookie: "__Host-csrf=test-csrf-token" }
})

// ---------------------------------------------------------------------------
// Tests for the SLA API client (Phase 47).
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

const MOCK_POLICIES = [
  { id: 1, org_id: "acme-org", severity: "critical", deadline_days: 7, enabled: true, created_at: null, updated_at: null },
  { id: 2, org_id: "acme-org", severity: "high", deadline_days: 14, enabled: true, created_at: null, updated_at: null },
  { id: 3, org_id: "acme-org", severity: "medium", deadline_days: 30, enabled: true, created_at: null, updated_at: null },
  { id: 4, org_id: "acme-org", severity: "low", deadline_days: 90, enabled: true, created_at: null, updated_at: null },
]

const MOCK_SUMMARY = {
  critical: { open: 5, breached: 2, breached_pct: 0.4 },
  high: { open: 10, breached: 1, breached_pct: 0.1 },
  medium: { open: 20, breached: 0, breached_pct: 0.0 },
  low: { open: 3, breached: 0, breached_pct: 0.0 },
}

async function loadModule() {
  return import("../../frontend/lib/client/sla-api.ts")
}

// ── listSlaPolicies ───────────────────────────────────────────────────────────

test("listSlaPolicies: fetches policies with org_id query param", async () => {
  const { mock, calls } = makeFetchMock({ policies: MOCK_POLICIES })
  ;(globalThis as any).fetch = mock

  const { listSlaPolicies } = await loadModule()
  const result = await listSlaPolicies("acme-org")

  assert.equal(calls.length, 1)
  assert.ok(calls[0].url.includes("org_id=acme-org"))
  assert.equal(result.length, 4)
  assert.equal(result[0].severity, "critical")
  assert.equal(result[0].deadline_days, 7)
})

test("listSlaPolicies: returns empty array on missing policies key", async () => {
  const { mock } = makeFetchMock({})
  ;(globalThis as any).fetch = mock

  const { listSlaPolicies } = await loadModule()
  const result = await listSlaPolicies("acme-org")
  assert.deepEqual(result, [])
})

test("listSlaPolicies: throws SlaApiError on non-2xx response", async () => {
  const { mock } = makeFetchMock({ detail: "Not found" }, 404)
  ;(globalThis as any).fetch = mock

  const { listSlaPolicies } = await loadModule()
  await assert.rejects(() => listSlaPolicies("acme-org"), (err: any) => {
    assert.equal(err.status, 404)
    return true
  })
})

// ── updateSlaPolicy ───────────────────────────────────────────────────────────

test("updateSlaPolicy: sends PUT with correct url and body", async () => {
  const updated = { ...MOCK_POLICIES[0], deadline_days: 5 }
  const { mock, calls } = makeFetchMock({ policy: updated })
  ;(globalThis as any).fetch = mock

  const { updateSlaPolicy } = await loadModule()
  const result = await updateSlaPolicy("acme-org", "critical", { deadline_days: 5, enabled: true })

  assert.equal(calls[0].init?.method, "PUT")
  assert.ok(calls[0].url.includes("/sla-policies/critical"))
  assert.ok(calls[0].url.includes("org_id=acme-org"))
  assert.equal(result.deadline_days, 5)
})

// ── getBreachSummary ──────────────────────────────────────────────────────────

test("getBreachSummary: fetches summary with org_id", async () => {
  const { mock, calls } = makeFetchMock({ summary: MOCK_SUMMARY })
  ;(globalThis as any).fetch = mock

  const { getBreachSummary } = await loadModule()
  const result = await getBreachSummary("acme-org")

  assert.ok(calls[0].url.includes("org_id=acme-org"))
  assert.equal(result.critical.breached, 2)
  assert.equal(result.high.open, 10)
})

// ── triggerRecompute ──────────────────────────────────────────────────────────

test("triggerRecompute: sends POST and returns updated count", async () => {
  const { mock, calls } = makeFetchMock({ ok: true, updated: 42 })
  ;(globalThis as any).fetch = mock

  const { triggerRecompute } = await loadModule()
  const result = await triggerRecompute("acme-org")

  assert.equal(calls[0].init?.method, "POST")
  assert.ok(calls[0].url.includes("/sla/recompute"))
  assert.equal(result.updated, 42)
})

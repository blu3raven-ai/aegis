import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for SLA policies page data flows (Phase 47).
// Tests the API client layer exercised by the page, consistent with the
// notification-rules-page.test.ts approach.
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

const MOCK_POLICIES = [
  { id: 1, org_id: "acme-org", severity: "critical", deadline_days: 7, enabled: true, created_at: null, updated_at: null },
  { id: 2, org_id: "acme-org", severity: "high", deadline_days: 14, enabled: true, created_at: null, updated_at: null },
  { id: 3, org_id: "acme-org", severity: "medium", deadline_days: 30, enabled: true, created_at: null, updated_at: null },
  { id: 4, org_id: "acme-org", severity: "low", deadline_days: 90, enabled: true, created_at: null, updated_at: null },
]

// ── Page load ─────────────────────────────────────────────────────────────────

test("page load: listSlaPolicies fetches four severity policies", async () => {
  const { mock, calls } = makeFetchMock({ policies: MOCK_POLICIES })
  ;(globalThis as any).fetch = mock

  const { listSlaPolicies } = await loadModule()
  const policies = await listSlaPolicies("acme-org")

  assert.equal(calls.length, 1)
  assert.equal(policies.length, 4)
  const severities = policies.map((p) => p.severity)
  assert.ok(severities.includes("critical"))
  assert.ok(severities.includes("high"))
  assert.ok(severities.includes("medium"))
  assert.ok(severities.includes("low"))
})

// ── Save flow ─────────────────────────────────────────────────────────────────

test("save flow: updateSlaPolicy PUTs new deadline and returns updated policy", async () => {
  const updated = { ...MOCK_POLICIES[0], deadline_days: 3 }
  const { mock, calls } = makeFetchMock({ policy: updated })
  ;(globalThis as any).fetch = mock

  const { updateSlaPolicy } = await loadModule()
  const result = await updateSlaPolicy("acme-org", "critical", { deadline_days: 3, enabled: true })

  assert.equal(calls[0].init?.method, "PUT")
  assert.equal(result.deadline_days, 3)
  assert.equal(result.severity, "critical")
})

test("save flow: updateSlaPolicy propagates 422 error", async () => {
  const { mock } = makeFetchMock({ detail: "deadline_days must be greater than 0" }, 422)
  ;(globalThis as any).fetch = mock

  const { updateSlaPolicy, SlaApiError } = await loadModule()
  await assert.rejects(
    () => updateSlaPolicy("acme-org", "critical", { deadline_days: 0, enabled: true }),
    (err: any) => {
      assert.ok(err instanceof SlaApiError)
      assert.equal(err.status, 422)
      return true
    },
  )
})

// ── Toggle enabled ────────────────────────────────────────────────────────────

test("disable policy: sends enabled=false in payload", async () => {
  const disabled = { ...MOCK_POLICIES[1], enabled: false }
  const { mock, calls } = makeFetchMock({ policy: disabled })
  ;(globalThis as any).fetch = mock

  const { updateSlaPolicy } = await loadModule()
  const result = await updateSlaPolicy("acme-org", "high", { deadline_days: 14, enabled: false })

  const body = JSON.parse(calls[0].init?.body as string)
  assert.equal(body.enabled, false)
  assert.equal(result.enabled, false)
})

// ── Recompute ─────────────────────────────────────────────────────────────────

test("recompute: POSTs and returns count", async () => {
  const { mock } = makeFetchMock({ ok: true, updated: 17 })
  ;(globalThis as any).fetch = mock

  const { triggerRecompute } = await loadModule()
  const result = await triggerRecompute("acme-org")
  assert.equal(result.updated, 17)
})

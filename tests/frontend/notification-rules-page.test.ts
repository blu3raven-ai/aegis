import test, { beforeEach } from "node:test"
import assert from "node:assert/strict"

// apiClient requires a CSRF cookie for POST/PUT/DELETE requests
beforeEach(() => {
  ;(globalThis as any).document = { cookie: "__Host-csrf=test-csrf-token" }
})

// ---------------------------------------------------------------------------
// Tests for the notification routing rules page data flows, exercised through
// the rules API client (same approach as notifications-page.test.ts).
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

function makeNoContentMock() {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), init })
    return new Response(null, { status: 204 })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../frontend/lib/client/notification-rules-api.ts")
}

// ── Page load ────────────────────────────────────────────────────────────────

test("page load: listRules fetches rules for the org", async () => {
  const rules = [
    {
      id: "nr_abc123",
      org_id: "example-org",
      name: "Crits to sec-channel",
      enabled: true,
      priority: 10,
      channel_id: 1,
      conditions: { field: "severity", op: "eq", value: "critical" },
      created_at: "2026-05-01T00:00:00Z",
      updated_at: "2026-05-01T00:00:00Z",
    },
  ]
  const { mock, calls } = makeFetchMock({ rules })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRules } = await loadModule()
  const result = await listRules("example-org")

  assert.equal(calls.length, 1)
  assert.ok(calls[0].url.includes("/api/v1/notification-rules"))
  assert.ok(calls[0].url.includes("org_id=example-org"))
  assert.equal(result.length, 1)
  assert.equal(result[0].name, "Crits to sec-channel")
})

test("page load: listRules returns empty array for org with no rules", async () => {
  const { mock, calls } = makeFetchMock({ rules: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRules } = await loadModule()
  const result = await listRules("example-org")

  assert.equal(calls.length, 1)
  assert.deepEqual(result, [])
})

// ── Create flow ───────────────────────────────────────────────────────────────

test("create flow: POST builds correct request body", async () => {
  const created = {
    id: "nr_new001",
    org_id: "example-org",
    name: "Secrets rule",
    enabled: true,
    priority: 20,
    channel_id: 5,
    conditions: { field: "scanner", op: "eq", value: "secrets" },
    created_at: "2026-05-20T00:00:00Z",
    updated_at: "2026-05-20T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(created, 201)
  globalThis.fetch = mock as unknown as typeof fetch

  const { createRule } = await loadModule()
  const result = await createRule({
    org_id: "example-org",
    name: "Secrets rule",
    channel_id: 5,
    conditions: { field: "scanner", op: "eq", value: "secrets" },
    priority: 20,
  })

  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, "/api/v1/notification-rules")
  const body = JSON.parse(calls[0].init!.body as string)
  assert.equal(body.name, "Secrets rule")
  assert.equal(body.channel_id, 5)
  assert.equal(body.priority, 20)
  assert.equal(result.id, "nr_new001")
})

// ── Update flow ───────────────────────────────────────────────────────────────

test("update flow: PUT sends to correct URL with org_id query param", async () => {
  const updated = {
    id: "nr_abc123",
    org_id: "example-org",
    name: "Updated name",
    enabled: false,
    priority: 15,
    channel_id: 1,
    conditions: {},
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-05-25T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(updated)
  globalThis.fetch = mock as unknown as typeof fetch

  const { updateRule } = await loadModule()
  const result = await updateRule("nr_abc123", "example-org", { name: "Updated name", enabled: false })

  assert.equal(calls.length, 1)
  assert.ok(calls[0].url.includes("/api/v1/notification-rules/nr_abc123"))
  assert.ok(calls[0].url.includes("org_id=example-org"))
  assert.equal(calls[0].init!.method, "PUT")
  assert.equal(result.name, "Updated name")
  assert.equal(result.enabled, false)
})

// ── Delete flow ───────────────────────────────────────────────────────────────

test("delete flow: DELETE sends 204 to correct URL", async () => {
  const { mock, calls } = makeNoContentMock()
  globalThis.fetch = mock as unknown as typeof fetch

  const { deleteRule } = await loadModule()
  await deleteRule("nr_abc123", "example-org")

  assert.equal(calls.length, 1)
  assert.ok(calls[0].url.includes("/api/v1/notification-rules/nr_abc123"))
  assert.ok(calls[0].url.includes("org_id=example-org"))
  assert.equal(calls[0].init!.method, "DELETE")
})

// ── Preview: single rule ──────────────────────────────────────────────────────

test("preview single rule: POST to /preview with rule payload", async () => {
  const previewResult = { matched: true, channel_id: 2, rule_name: "crits rule" }
  const { mock, calls } = makeFetchMock(previewResult)
  globalThis.fetch = mock as unknown as typeof fetch

  const { previewRule } = await loadModule()
  const result = await previewRule({
    rule: {
      org_id: "example-org",
      name: "crits rule",
      channel_id: 2,
      conditions: { field: "severity", op: "eq", value: "critical" },
    },
    finding: { severity: "critical", scanner: "secrets", repo_id: "repo-1" },
  })

  assert.equal(calls.length, 1)
  assert.ok(calls[0].url.includes("/api/v1/notification-rules/preview"))
  assert.equal(calls[0].init!.method, "POST")
  assert.equal(result.matched, true)
  assert.equal(result.channel_id, 2)
})

test("preview single rule: no match returns matched=false", async () => {
  const previewResult = { matched: false, channel_id: null, rule_name: "crits rule" }
  const { mock } = makeFetchMock(previewResult)
  globalThis.fetch = mock as unknown as typeof fetch

  const { previewRule } = await loadModule()
  const result = await previewRule({
    rule: {
      org_id: "example-org",
      name: "crits rule",
      channel_id: 2,
      conditions: { field: "severity", op: "eq", value: "critical" },
    },
    finding: { severity: "low", scanner: "dependencies", repo_id: "repo-1" },
  })

  assert.equal(result.matched, false)
  assert.equal(result.channel_id, null)
})

// ── Preview: org evaluation ───────────────────────────────────────────────────

test("preview org: POST with org_id returns breakdown", async () => {
  const orgResult = {
    matched_channel_ids: [3],
    breakdown: [
      { rule_id: "nr_r1", rule_name: "high+ rule", priority: 10, channel_id: 3, matched: true },
      { rule_id: "nr_r2", rule_name: "secrets rule", priority: 20, channel_id: 4, matched: false },
    ],
  }
  const { mock, calls } = makeFetchMock(orgResult)
  globalThis.fetch = mock as unknown as typeof fetch

  const { previewOrg } = await loadModule()
  const result = await previewOrg({
    org_id: "example-org",
    finding: { severity: "high", scanner: "code_scanning", repo_id: "repo-xyz" },
  })

  assert.equal(calls.length, 1)
  assert.equal(result.matched_channel_ids.length, 1)
  assert.equal(result.matched_channel_ids[0], 3)
  assert.equal(result.breakdown.length, 2)
  assert.equal(result.breakdown[0].matched, true)
  assert.equal(result.breakdown[1].matched, false)
})

// ── Error handling ────────────────────────────────────────────────────────────

test("api error: non-ok response throws RulesApiError", async () => {
  const { mock } = makeFetchMock({ detail: "rule not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRules } = await loadModule()
  await assert.rejects(
    () => listRules("example-org"),
    (err: Error) => {
      assert.ok(err.message.includes("404"))
      return true
    }
  )
})

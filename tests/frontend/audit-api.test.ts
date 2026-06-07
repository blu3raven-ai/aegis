import test from "node:test"
import assert from "node:assert/strict"
import { ApiClientError } from "../../frontend/lib/client/api-client.types.ts"

// ---------------------------------------------------------------------------
// Minimal fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string }

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    calls.push({ url: input.toString() })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../frontend/lib/client/audit-api.ts")
}

// ---------------------------------------------------------------------------
// URL construction
// ---------------------------------------------------------------------------

test("listAuditEvents builds URL with no filters", async () => {
  const body = { events: [], total: 0, has_more: false }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  const result = await listAuditEvents({})

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/audit/events")
  assert.equal(result.events.length, 0)
  assert.equal(result.total, 0)
  assert.equal(result.has_more, false)
})

test("listAuditEvents encodes action filter", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await listAuditEvents({ action: "notification.destination.created" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("action"), "notification.destination.created")
})

test("listAuditEvents encodes actor_id filter", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await listAuditEvents({ actor_id: "user-abc-123" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("actor_id"), "user-abc-123")
})

test("listAuditEvents encodes resource_type filter", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await listAuditEvents({ resource_type: "notification_destination" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("resource_type"), "notification_destination")
})

test("listAuditEvents encodes since and until", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await listAuditEvents({
    since: "2026-05-01T00:00:00Z",
    until: "2026-05-31T23:59:59Z",
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("since"), "2026-05-01T00:00:00Z")
  assert.equal(url.searchParams.get("until"), "2026-05-31T23:59:59Z")
})

test("listAuditEvents encodes limit and offset for pagination", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await listAuditEvents({ limit: 50, offset: 100 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), "50")
  assert.equal(url.searchParams.get("offset"), "100")
})

test("listAuditEvents omits undefined filters from URL", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await listAuditEvents({ action: undefined, actor_id: undefined })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.has("action"), false)
  assert.equal(url.searchParams.has("actor_id"), false)
})

test("listAuditEvents returns full event shape", async () => {
  const event = {
    id: 42,
    org_id: "example-org",
    actor_id: "user-1",
    actor_email: "alice@example.com",
    actor_role: "admin",
    action: "correlation.rule.created",
    resource_type: "correlation_rule",
    resource_id: "rule-99",
    request_method: "POST",
    request_path: "/api/v1/correlation/rules",
    request_ip: "10.0.0.1",
    user_agent: "Mozilla/5.0",
    status_code: 201,
    occurred_at: "2026-05-30T12:00:00Z",
    changes: { before: null, after: { name: "New rule" } },
    metadata: { source: "ui" },
  }
  const body = { events: [event], total: 1, has_more: false }
  const { mock } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  const result = await listAuditEvents({})

  assert.equal(result.events.length, 1)
  assert.equal(result.events[0].id, 42)
  assert.equal(result.events[0].actor_email, "alice@example.com")
  assert.equal(result.events[0].action, "correlation.rule.created")
  assert.equal(result.events[0].status_code, 201)
  assert.deepEqual(result.events[0].changes, { before: null, after: { name: "New rule" } })
})

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

test("listAuditEvents throws on 404", async () => {
  const { mock } = makeFetchMock({ detail: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await assert.rejects(
    () => listAuditEvents({}),
    (e: unknown) => e instanceof ApiClientError && e.status === 404,
  )
})

test("listAuditEvents throws on 403", async () => {
  const { mock } = makeFetchMock({ detail: "forbidden" }, 403)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await assert.rejects(
    () => listAuditEvents({}),
    (e: unknown) => e instanceof ApiClientError && e.status === 403,
  )
})

test("listAuditEvents throws on 500", async () => {
  const { mock } = makeFetchMock({ detail: "server error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await assert.rejects(
    () => listAuditEvents({}),
    (e: unknown) => e instanceof ApiClientError && e.status === 500,
  )
})

test("listAuditEvents encodes all filters together", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadModule()
  await listAuditEvents({
    action: "integration.tool.updated",
    actor_id: "service:scanner",
    resource_type: "integration",
    resource_id: "int-7",
    since: "2026-05-01T00:00:00Z",
    limit: 25,
    offset: 25,
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("action"), "integration.tool.updated")
  assert.equal(url.searchParams.get("actor_id"), "service:scanner")
  assert.equal(url.searchParams.get("resource_type"), "integration")
  assert.equal(url.searchParams.get("resource_id"), "int-7")
  assert.equal(url.searchParams.get("since"), "2026-05-01T00:00:00Z")
  assert.equal(url.searchParams.get("limit"), "25")
  assert.equal(url.searchParams.get("offset"), "25")
})

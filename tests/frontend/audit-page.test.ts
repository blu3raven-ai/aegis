import test from "node:test"
import assert from "node:assert/strict"
import { ApiClientError } from "../../frontend/lib/client/api-client.types.ts"

// ---------------------------------------------------------------------------
// Tests for audit-api.ts that simulate page-level integration scenarios:
// filter state changes → different API URLs, pagination offset calculation,
// and drawer data shapes.
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

async function loadAuditApi() {
  return import("../../frontend/lib/client/audit-api.ts")
}

// ---------------------------------------------------------------------------
// Filter changes → refetch with correct params
// ---------------------------------------------------------------------------

test("action filter is reflected in URL", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  await listAuditEvents({ action: "notification.destination.created" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("action"), "notification.destination.created")
})

test("actor_id filter is reflected in URL", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  await listAuditEvents({ actor_id: "user-abc" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("actor_id"), "user-abc")
})

test("resource_type filter is reflected in URL", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  await listAuditEvents({ resource_type: "correlation_rule" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("resource_type"), "correlation_rule")
})

test("7d window sends since timestamp", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  const since = new Date()
  since.setDate(since.getDate() - 7)
  await listAuditEvents({ since: since.toISOString() })

  const url = new URL(calls[0].url, "http://localhost")
  assert.ok(url.searchParams.has("since"), "since param should be present for 7d window")
  assert.ok(!url.searchParams.has("until"), "until should not be set for open-ended query")
})

test("all-time window omits since param", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  // Page passes since: undefined for "all time"
  await listAuditEvents({})

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.has("since"), false)
})

// ---------------------------------------------------------------------------
// Pagination offset calculation
// ---------------------------------------------------------------------------

test("page 1 sends offset 0", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  await listAuditEvents({ limit: 25, offset: 0 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("offset"), "0")
  assert.equal(url.searchParams.get("limit"), "25")
})

test("page 2 sends offset 25 with limit 25", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  await listAuditEvents({ limit: 25, offset: 25 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("offset"), "25")
})

test("page 5 sends offset 100 with limit 25", async () => {
  const { mock, calls } = makeFetchMock({ events: [], total: 0, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  await listAuditEvents({ limit: 25, offset: 100 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("offset"), "100")
})

// ---------------------------------------------------------------------------
// Drawer data shapes — full event payload
// ---------------------------------------------------------------------------

test("drawer receives event with changes diff shape", async () => {
  const event = {
    id: 1,
    org_id: "example-org",
    actor_id: "user-1",
    actor_email: "alice@example.com",
    actor_role: "admin",
    action: "notification.destination.updated",
    resource_type: "notification_destination",
    resource_id: "dest-42",
    request_method: "PATCH",
    request_path: "/api/v1/notification/destinations/42",
    request_ip: "192.168.1.10",
    user_agent: "Mozilla/5.0",
    status_code: 200,
    occurred_at: "2026-05-30T10:00:00Z",
    changes: {
      before: { status: "active", event_filter: { min_severity: "high" } },
      after: { status: "disabled", event_filter: { min_severity: "critical" } },
    },
    metadata: { via: "settings-ui" },
  }
  const { mock } = makeFetchMock({ events: [event], total: 1, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  const result = await listAuditEvents({})

  assert.equal(result.events.length, 1)
  const ev = result.events[0]
  assert.equal(ev.action, "notification.destination.updated")
  assert.equal(ev.resource_id, "dest-42")
  assert.ok(ev.changes != null, "changes should be non-null")
  assert.equal((ev.changes as Record<string, unknown>)?.before != null, true)
  assert.equal((ev.changes as Record<string, unknown>)?.after != null, true)
})

test("drawer receives service actor without email", async () => {
  const event = {
    id: 2,
    org_id: "example-org",
    actor_id: "service:scanner",
    action: "correlation.rule.evaluated",
    resource_type: "correlation_rule",
    status_code: 200,
    occurred_at: "2026-05-30T11:00:00Z",
  }
  const { mock } = makeFetchMock({ events: [event], total: 1, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  const result = await listAuditEvents({})

  const ev = result.events[0]
  assert.equal(ev.actor_id, "service:scanner")
  assert.equal(ev.actor_email, undefined)
})

test("drawer receives event without changes", async () => {
  const event = {
    id: 3,
    org_id: "example-org",
    actor_id: "user-2",
    action: "integration.tool.viewed",
    resource_type: "integration",
    status_code: 200,
    occurred_at: "2026-05-30T12:00:00Z",
    // no changes field
  }
  const { mock } = makeFetchMock({ events: [event], total: 1, has_more: false })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  const result = await listAuditEvents({})

  const ev = result.events[0]
  assert.equal(ev.changes, undefined)
})

// ---------------------------------------------------------------------------
// Error states
// ---------------------------------------------------------------------------

test("403 from audit endpoint throws ApiClientError", async () => {
  const { mock } = makeFetchMock({ detail: "Audit log disabled" }, 403)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  await assert.rejects(
    () => listAuditEvents({}),
    (e: unknown) => e instanceof ApiClientError && e.status === 403,
  )
})

test("error message includes status code for diagnosis", async () => {
  const { mock } = makeFetchMock({ detail: "internal error" }, 503)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listAuditEvents } = await loadAuditApi()
  let caught: Error | null = null
  try {
    await listAuditEvents({})
  } catch (e) {
    caught = e as Error
  }
  assert.ok(caught != null)
  assert.ok(caught.message.includes("503"))
})

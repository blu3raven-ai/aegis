import test, { beforeEach } from "node:test"
import assert from "node:assert/strict"

// apiClient requires a CSRF cookie for POST/PUT/DELETE requests
beforeEach(() => {
  ;(globalThis as any).document = { cookie: "__Host-csrf=test-csrf-token" }
})

// ---------------------------------------------------------------------------
// Integration tests for the notifications page data flows, exercised through
// the destinations API client (same approach as insights-page.test.ts).
// Tests simulate the create/edit/delete flows the page orchestrates.
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
  // Node resolves path aliases differently; use the real filesystem path.
  return import("../../frontend/lib/client/destinations-api.ts")
}

// ---------------------------------------------------------------------------
// Page load — renders destinations list
// ---------------------------------------------------------------------------

test("page load: listDestinations fetches org destinations", async () => {
  // listDestinations speaks GraphQL — wrap response in {data: {notifications: {destinations: [...]}}}
  // with the camelCase resolver shape (configJson / eventFilterJson strings).
  const payload = {
    data: {
      notifications: {
        destinations: [
          {
            id: 1,
            destinationType: "slack",
            name: "Sec Slack",
            configJson: JSON.stringify({ webhook_url: "https://hooks.slack.com/x" }),
            enabled: true,
            eventFilterJson: JSON.stringify({}),
            createdAt: "2026-05-01T00:00:00Z",
            updatedAt: "2026-05-01T00:00:00Z",
          },
          {
            id: 2,
            destinationType: "email",
            name: "PagerDuty mail",
            configJson: JSON.stringify({ to_addresses: ["pager@example.com"] }),
            enabled: false,
            eventFilterJson: JSON.stringify({ min_severity: "high" }),
            createdAt: "2026-05-02T00:00:00Z",
            updatedAt: "2026-05-02T00:00:00Z",
          },
        ],
      },
    },
  }
  const { mock, calls } = makeFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  const result = await listDestinations("example-org")

  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(result.length, 2)
  assert.equal(result[0].name, "Sec Slack")
  assert.equal(result[1].enabled, false)
})

// ---------------------------------------------------------------------------
// Create flow
// ---------------------------------------------------------------------------

test("create flow: POST slack destination builds correct request", async () => {
  const created = {
    id: 3,
    org_id: "example-org",
    destination_type: "slack",
    name: "Ops channel",
    config: { webhook_url: "https://hooks.slack.com/ops" },
    enabled: true,
    event_filter: { event_types: ["chain.created"], min_severity: "critical" },
    created_at: "2026-05-20T00:00:00Z",
    updated_at: "2026-05-20T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(created, 201)
  globalThis.fetch = mock as unknown as typeof fetch

  const { createDestination } = await loadModule()
  const result = await createDestination({
    org_id: "example-org",
    destination_type: "slack",
    name: "Ops channel",
    config: { webhook_url: "https://hooks.slack.com/ops" },
    enabled: true,
    event_filter: { event_types: ["chain.created"], min_severity: "critical" },
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations")
  assert.equal(calls[0].init?.method, "POST")
  assert.equal(result.id, 3)
  assert.equal(result.destination_type, "slack")
})

test("create flow: POST webhook destination includes optional secret", async () => {
  const created = {
    id: 4,
    org_id: "example-org",
    destination_type: "webhook",
    name: "SIEM hook",
    config: { url: "https://siem.example.com/aegis", secret: "s3cr3t" },
    enabled: true,
    event_filter: {},
    created_at: "2026-05-20T00:00:00Z",
    updated_at: "2026-05-20T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(created, 201)
  globalThis.fetch = mock as unknown as typeof fetch

  const { createDestination } = await loadModule()
  const result = await createDestination({
    org_id: "example-org",
    destination_type: "webhook",
    name: "SIEM hook",
    config: { url: "https://siem.example.com/aegis", secret: "s3cr3t" },
  })

  const body = JSON.parse(calls[0].init?.body as string)
  assert.equal(body.config.secret, "s3cr3t")
  assert.equal(result.config.url, "https://siem.example.com/aegis")
})

test("create flow: POST email destination with multiple addresses", async () => {
  const created = {
    id: 5,
    org_id: "example-org",
    destination_type: "email",
    name: "Email blast",
    config: { to_addresses: ["a@example.com", "b@example.com"] },
    enabled: true,
    event_filter: {},
    created_at: "2026-05-20T00:00:00Z",
    updated_at: "2026-05-20T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(created, 201)
  globalThis.fetch = mock as unknown as typeof fetch

  const { createDestination } = await loadModule()
  const result = await createDestination({
    org_id: "example-org",
    destination_type: "email",
    name: "Email blast",
    config: { to_addresses: ["a@example.com", "b@example.com"] },
  })

  const body = JSON.parse(calls[0].init?.body as string)
  assert.deepEqual(body.config.to_addresses, ["a@example.com", "b@example.com"])
  assert.equal(result.id, 5)
})

// ---------------------------------------------------------------------------
// Edit flow
// ---------------------------------------------------------------------------

test("edit flow: PUT updates name and enabled state", async () => {
  const updated = {
    id: 1,
    org_id: "example-org",
    destination_type: "slack",
    name: "Renamed channel",
    config: { webhook_url: "https://hooks.slack.com/x" },
    enabled: false,
    event_filter: {},
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-05-25T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(updated)
  globalThis.fetch = mock as unknown as typeof fetch

  const { updateDestination } = await loadModule()
  const result = await updateDestination(1, { name: "Renamed channel", enabled: false })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/1")
  assert.equal(calls[0].init?.method, "PUT")
  assert.equal(result.name, "Renamed channel")
  assert.equal(result.enabled, false)
})

test("edit flow: PUT updates event_filter", async () => {
  const updated = {
    id: 2,
    org_id: "example-org",
    destination_type: "email",
    name: "PagerDuty mail",
    config: { to_addresses: ["pager@example.com"] },
    enabled: true,
    event_filter: { event_types: ["finding.created"], min_severity: "high" },
    created_at: "2026-05-02T00:00:00Z",
    updated_at: "2026-05-26T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(updated)
  globalThis.fetch = mock as unknown as typeof fetch

  const { updateDestination } = await loadModule()
  const result = await updateDestination(2, {
    event_filter: { event_types: ["finding.created"], min_severity: "high" },
  })

  const body = JSON.parse(calls[0].init?.body as string)
  assert.deepEqual(body.event_filter.event_types, ["finding.created"])
  assert.equal(result.event_filter.min_severity, "high")
})

// ---------------------------------------------------------------------------
// Delete flow
// ---------------------------------------------------------------------------

test("delete flow: DELETE removes destination by id", async () => {
  const { mock, calls } = makeNoContentMock()
  globalThis.fetch = mock as unknown as typeof fetch

  const { deleteDestination } = await loadModule()
  await deleteDestination(7)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/7")
  assert.equal(calls[0].init?.method, "DELETE")
})

test("delete flow: throws typed error on 404", async () => {
  const { mock } = makeFetchMock({ detail: "destination not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { deleteDestination } = await loadModule()
  await assert.rejects(
    () => deleteDestination(999),
    (err: any) => {
      assert.equal(err.status, 404)
      return true
    },
  )
})

// ---------------------------------------------------------------------------
// Delivery history
// ---------------------------------------------------------------------------

test("delivery history: fetches last 25 deliveries for destination", async () => {
  // listDeliveries speaks GraphQL — wrap the rows in {data: {notifications: {deliveries: [...]}}}
  // with the camelCase resolver shape.
  const payload = {
    data: {
      notifications: {
        deliveries: [
          { id: "1", destinationId: 1, eventId: "evt-1", eventType: "chain.created", status: "delivered", payloadSummary: null, responseCode: 200, error: null, attemptedAt: "2026-05-20T10:00:00Z" },
          { id: "2", destinationId: 1, eventId: "evt-2", eventType: "finding.created", status: "failed", payloadSummary: null, responseCode: null, error: "connection refused", attemptedAt: "2026-05-20T11:00:00Z" },
        ],
      },
    },
  }
  const { mock, calls } = makeFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  const result = await listDeliveries(1, 25)

  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(result.length, 2)
  assert.equal(result[1].status, "failed")
  assert.equal(result[1].error, "connection refused")
})

test("delivery history: returns empty array when no deliveries", async () => {
  const { mock } = makeFetchMock({ data: { notifications: { deliveries: [] } } })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  const result = await listDeliveries(5)
  assert.deepEqual(result, [])
})

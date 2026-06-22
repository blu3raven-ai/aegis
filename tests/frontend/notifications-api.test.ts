import test, { beforeEach } from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// destinations-api is a mixed surface:
//   - listDestinations / listDeliveries → GraphQL (Query.notifications.*)
//   - createDestination / updateDestination / deleteDestination / testDestination
//     → REST under /api/v1/notifications/destinations
// Tests cover both transports.
// ---------------------------------------------------------------------------

// apiClient requires a CSRF cookie for POST/PUT/DELETE
beforeEach(() => {
  ;(globalThis as { document?: { cookie: string } }).document = {
    cookie: "__Host-csrf=test-csrf-token",
  }
})

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

function makeEmptyMock(status = 204) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), init })
    return new Response(null, { status })
  }
  return { mock, calls }
}

interface GqlCall {
  url: string
  body: { operationName: string; variables: Record<string, unknown> }
}

function makeGqlFetchMock(payload: unknown, status = 200) {
  const calls: GqlCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({
      url: input.toString(),
      body: JSON.parse(init?.body as string) as GqlCall["body"],
    })
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../frontend/lib/client/destinations-api.ts")
}

// ---------------------------------------------------------------------------
// listDestinations — GraphQL
// ---------------------------------------------------------------------------

test("listDestinations POSTs to /api/v1/graphql with operationName NotificationDestinations", async () => {
  const payload = { data: { notifications: { destinations: [] } } }
  const { mock, calls } = makeGqlFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  await listDestinations()

  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(calls[0].body.operationName, "NotificationDestinations")
})

test("listDestinations unwraps config and eventFilter from the GraphQL row", async () => {
  const payload = {
    data: {
      notifications: {
        destinations: [
          {
            id: 1,
            destinationType: "slack",
            name: "Sec channel",
            config: { webhook_url: "https://hooks.slack.com/xxx" },
            enabled: true,
            eventFilter: { min_severity: "critical" },
            createdAt: "2026-05-01T00:00:00Z",
            updatedAt: "2026-05-01T00:00:00Z",
          },
        ],
      },
    },
  }
  const { mock } = makeGqlFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  const result = await listDestinations()

  assert.equal(result.length, 1)
  assert.equal(result[0].name, "Sec channel")
  assert.equal(result[0].destination_type, "slack")
  assert.deepEqual(result[0].config, { webhook_url: "https://hooks.slack.com/xxx" })
  assert.equal(result[0].event_filter.min_severity, "critical")
})

test("listDestinations falls back to empty objects when config and eventFilter are absent", async () => {
  const payload = {
    data: {
      notifications: {
        destinations: [
          {
            id: 2,
            destinationType: "webhook",
            name: "Broken config",
            config: null,
            enabled: false,
            eventFilter: null,
            createdAt: null,
            updatedAt: null,
          },
        ],
      },
    },
  }
  const { mock } = makeGqlFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  const result = await listDestinations()

  assert.deepEqual(result[0].config, {})
  assert.deepEqual(result[0].event_filter, {})
  assert.equal(result[0].created_at, "")
})

test("listDestinations throws when GraphQL response has errors", async () => {
  const { mock } = makeGqlFetchMock({ errors: [{ message: "forbidden" }] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  await assert.rejects(() => listDestinations(), /forbidden/)
})

// ---------------------------------------------------------------------------
// createDestination — REST
// ---------------------------------------------------------------------------

test("createDestination POSTs to /api/v1/notifications/destinations", async () => {
  const created = {
    id: 2,
    destination_type: "webhook",
    name: "My webhook",
    config: { url: "https://example.com/hook" },
    enabled: true,
    event_filter: {},
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-05-01T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(created, 201)
  globalThis.fetch = mock as unknown as typeof fetch

  const { createDestination } = await loadModule()
  const result = await createDestination({
    destination_type: "webhook",
    name: "My webhook",
    config: { url: "https://example.com/hook" },
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations")
  assert.equal(calls[0].init?.method, "POST")
  assert.equal(result.id, 2)
})

test("createDestination throws on 422 validation error", async () => {
  const { mock } = makeFetchMock(
    { detail: "destination_type must be one of ['email', 'slack', 'webhook']" },
    422,
  )
  globalThis.fetch = mock as unknown as typeof fetch

  const { createDestination } = await loadModule()
  await assert.rejects(
    () =>
      createDestination({
        destination_type: "slack",
        name: "bad",
        config: {},
      }),
    (err: { status?: number }) => {
      assert.equal(err.status, 422)
      return true
    },
  )
})

// ---------------------------------------------------------------------------
// updateDestination — REST
// ---------------------------------------------------------------------------

test("updateDestination PUTs to /api/v1/notifications/destinations/:id", async () => {
  const updated = {
    id: 3,
    destination_type: "email",
    name: "Updated name",
    config: { to_addresses: ["sec@example.com"] },
    enabled: false,
    event_filter: {},
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-05-02T00:00:00Z",
  }
  const { mock, calls } = makeFetchMock(updated)
  globalThis.fetch = mock as unknown as typeof fetch

  const { updateDestination } = await loadModule()
  const result = await updateDestination(3, { name: "Updated name", enabled: false })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/3")
  assert.equal(calls[0].init?.method, "PUT")
  assert.equal(result.name, "Updated name")
})

test("updateDestination throws on 404", async () => {
  const { mock } = makeFetchMock({ detail: "destination not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { updateDestination } = await loadModule()
  await assert.rejects(
    () => updateDestination(999, { name: "x" }),
    (err: { status?: number }) => {
      assert.equal(err.status, 404)
      return true
    },
  )
})

// ---------------------------------------------------------------------------
// deleteDestination — REST
// ---------------------------------------------------------------------------

test("deleteDestination DELETEs /api/v1/notifications/destinations/:id", async () => {
  const { mock, calls } = makeEmptyMock(204)
  globalThis.fetch = mock as unknown as typeof fetch

  const { deleteDestination } = await loadModule()
  await deleteDestination(5)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/5")
  assert.equal(calls[0].init?.method, "DELETE")
})

// ---------------------------------------------------------------------------
// listDeliveries — GraphQL
// ---------------------------------------------------------------------------

test("listDeliveries POSTs to /api/v1/graphql with destinationId variable", async () => {
  const payload = { data: { notifications: { deliveries: [] } } }
  const { mock, calls } = makeGqlFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  await listDeliveries(7)

  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(calls[0].body.operationName, "NotificationDeliveries")
  assert.equal(calls[0].body.variables.destinationId, 7)
  assert.equal(calls[0].body.variables.limit, 50)
})

test("listDeliveries forwards explicit limit", async () => {
  const payload = { data: { notifications: { deliveries: [] } } }
  const { mock, calls } = makeGqlFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  await listDeliveries(2, 10)

  assert.equal(calls[0].body.variables.limit, 10)
})

test("listDeliveries unwraps and converts camelCase fields", async () => {
  const payload = {
    data: {
      notifications: {
        deliveries: [
          {
            id: "10",
            destinationId: 1,
            eventId: "evt-abc",
            eventType: "finding.created",
            status: "delivered",
            payloadSummary: "some-summary",
            responseCode: 200,
            error: null,
            attemptedAt: "2026-05-20T10:00:00Z",
          },
        ],
      },
    },
  }
  const { mock } = makeGqlFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  const result = await listDeliveries(1)

  assert.equal(result.length, 1)
  assert.equal(result[0].id, 10)
  assert.equal(result[0].destination_id, 1)
  assert.equal(result[0].event_id, "evt-abc")
  assert.equal(result[0].status, "delivered")
  assert.equal(result[0].response_code, 200)
})

// ---------------------------------------------------------------------------
// testDestination — REST
// ---------------------------------------------------------------------------

test("testDestination POSTs to /destinations/:id/test", async () => {
  const { mock, calls } = makeFetchMock({
    status: "delivered",
    channel: "slack",
    latency_ms: 234,
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { testDestination } = await loadModule()
  const result = await testDestination(7)

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/7/test")
  assert.equal(url.searchParams.has("org_id"), false)
  assert.equal(calls[0].init?.method, "POST")
  assert.equal(result.status, "delivered")
})

test("testDestination surfaces operational failure body (200 with status=failed)", async () => {
  const { mock } = makeFetchMock({
    status: "failed",
    channel: "webhook",
    latency_ms: 100,
    error: "webhook returned 500: boom",
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { testDestination } = await loadModule()
  const result = await testDestination(3, "example-org")
  assert.equal(result.status, "failed")
  assert.equal(result.error, "webhook returned 500: boom")
})

test("testDestination throws typed error on 404", async () => {
  const { mock } = makeFetchMock({ detail: "destination not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { testDestination } = await loadModule()
  await assert.rejects(
    () => testDestination(999, "example-org"),
    (err: { status?: number }) => {
      assert.equal(err.status, 404)
      return true
    },
  )
})

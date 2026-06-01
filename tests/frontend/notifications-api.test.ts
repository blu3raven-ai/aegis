import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock
// ---------------------------------------------------------------------------

interface FetchCall {
  url: string
  init?: RequestInit
}

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []

  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString()
    calls.push({ url, init })
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

async function loadModule() {
  return import("../../lib/client/destinations-api.ts")
}

// ---------------------------------------------------------------------------
// listDestinations
// ---------------------------------------------------------------------------

test("listDestinations builds correct URL with org_id", async () => {
  const destinations = [
    {
      id: 1,
      org_id: "example-org",
      destination_type: "slack",
      name: "Sec channel",
      config: { webhook_url: "https://hooks.slack.com/xxx" },
      enabled: true,
      event_filter: { min_severity: "critical" },
      created_at: "2026-05-01T00:00:00Z",
      updated_at: "2026-05-01T00:00:00Z",
    },
  ]
  const { mock, calls } = makeFetchMock({ destinations })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  const result = await listDestinations("example-org")

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations")
  assert.equal(url.searchParams.get("org_id"), "example-org")
  assert.equal(result.length, 1)
  assert.equal(result[0].name, "Sec channel")
})

test("listDestinations returns empty array on empty response", async () => {
  const { mock } = makeFetchMock({ destinations: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  const result = await listDestinations("example-org")
  assert.deepEqual(result, [])
})

test("listDestinations throws typed error on 403", async () => {
  const { mock } = makeFetchMock({ detail: "forbidden" }, 403)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  await assert.rejects(
    () => listDestinations("example-org"),
    (err: Error) => {
      assert.ok(err.message.includes("403"))
      return true
    },
  )
})

test("listDestinations throws on 500", async () => {
  const { mock } = makeFetchMock({ detail: "internal error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDestinations } = await loadModule()
  await assert.rejects(() => listDestinations("example-org"), /destinations-api: 500/)
})

// ---------------------------------------------------------------------------
// createDestination
// ---------------------------------------------------------------------------

test("createDestination POSTs to base URL with JSON body", async () => {
  const created = {
    id: 2,
    org_id: "example-org",
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
    org_id: "example-org",
    destination_type: "webhook",
    name: "My webhook",
    config: { url: "https://example.com/hook" },
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations")
  assert.equal(calls[0].init?.method, "POST")
  assert.equal(result.id, 2)
  assert.equal(result.name, "My webhook")
})

test("createDestination throws on 422 validation error", async () => {
  const { mock } = makeFetchMock({ detail: "destination_type must be one of ['email', 'slack', 'webhook']" }, 422)
  globalThis.fetch = mock as unknown as typeof fetch

  const { createDestination } = await loadModule()
  await assert.rejects(
    () =>
      createDestination({
        org_id: "example-org",
        destination_type: "slack",
        name: "bad",
        config: {},
      }),
    /destinations-api: 422/,
  )
})

// ---------------------------------------------------------------------------
// updateDestination
// ---------------------------------------------------------------------------

test("updateDestination PUTs to correct URL", async () => {
  const updated = {
    id: 3,
    org_id: "example-org",
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
  assert.equal(result.enabled, false)
})

test("updateDestination throws on 404", async () => {
  const { mock } = makeFetchMock({ detail: "destination not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { updateDestination } = await loadModule()
  await assert.rejects(() => updateDestination(999, { name: "x" }), /destinations-api: 404/)
})

// ---------------------------------------------------------------------------
// deleteDestination
// ---------------------------------------------------------------------------

test("deleteDestination sends DELETE to correct URL", async () => {
  const { mock, calls } = makeEmptyMock(204)
  globalThis.fetch = mock as unknown as typeof fetch

  const { deleteDestination } = await loadModule()
  await deleteDestination(5)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/5")
  assert.equal(calls[0].init?.method, "DELETE")
})

test("deleteDestination throws on 404", async () => {
  const { mock } = makeFetchMock({ detail: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { deleteDestination } = await loadModule()
  await assert.rejects(() => deleteDestination(999), /destinations-api: 404/)
})

// ---------------------------------------------------------------------------
// listDeliveries
// ---------------------------------------------------------------------------

test("listDeliveries builds URL with destinationId and default limit", async () => {
  const deliveries = [
    {
      id: 10,
      destination_id: 1,
      event_id: "evt-abc",
      event_type: "finding.created",
      status: "delivered",
      response_code: 200,
      attempted_at: "2026-05-20T10:00:00Z",
    },
  ]
  const { mock, calls } = makeFetchMock({ deliveries })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  const result = await listDeliveries(1)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/1/deliveries")
  assert.equal(url.searchParams.get("limit"), "50")
  assert.equal(result.length, 1)
  assert.equal(result[0].status, "delivered")
})

test("listDeliveries forwards custom limit", async () => {
  const { mock, calls } = makeFetchMock({ deliveries: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  await listDeliveries(2, 10)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), "10")
})

test("listDeliveries throws on 5xx", async () => {
  const { mock } = makeFetchMock({}, 503)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listDeliveries } = await loadModule()
  await assert.rejects(() => listDeliveries(1), /destinations-api: 503/)
})

// ---------------------------------------------------------------------------
// testDestination
// ---------------------------------------------------------------------------

test("testDestination POSTs to /destinations/:id/test with org_id query", async () => {
  const { mock, calls } = makeFetchMock({
    status: "delivered",
    channel: "slack",
    latency_ms: 234,
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { testDestination } = await loadModule()
  const result = await testDestination(7, "example-org")

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/notifications/destinations/7/test")
  assert.equal(url.searchParams.get("org_id"), "example-org")
  assert.equal(calls[0].init?.method, "POST")
  assert.equal(result.status, "delivered")
  assert.equal(result.channel, "slack")
  assert.equal(result.latency_ms, 234)
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
    /destinations-api: 404/,
  )
})

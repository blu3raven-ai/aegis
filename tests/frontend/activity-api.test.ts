import test from "node:test"
import assert from "node:assert/strict"

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
  return import("../../lib/client/activity-api.ts")
}

// ---------------------------------------------------------------------------
// listActivity URL construction
// ---------------------------------------------------------------------------

test("listActivity builds URL with no params", async () => {
  const body = { events: [], next_cursor: null }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  const result = await listActivity({})

  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, "/api/v1/activity")
  assert.equal(result.events.length, 0)
  assert.equal(result.next_cursor, null)
})

test("listActivity encodes types filter as comma-separated string", async () => {
  const { mock, calls } = makeFetchMock({ events: [], next_cursor: null })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({ types: ["finding.created", "scan.completed"] })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("types"), "finding.created,scan.completed")
})

test("listActivity encodes cursor param", async () => {
  const { mock, calls } = makeFetchMock({ events: [], next_cursor: null })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({ cursor: "abc123" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("cursor"), "abc123")
})

test("listActivity encodes repo_id filter", async () => {
  const { mock, calls } = makeFetchMock({ events: [], next_cursor: null })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({ repo_id: "acme-org/api" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("repo_id"), "acme-org/api")
})

test("listActivity encodes since/until params", async () => {
  const { mock, calls } = makeFetchMock({ events: [], next_cursor: null })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({ since: "2026-01-01T00:00:00Z", until: "2026-01-31T23:59:59Z" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("since"), "2026-01-01T00:00:00Z")
  assert.equal(url.searchParams.get("until"), "2026-01-31T23:59:59Z")
})

test("listActivity encodes limit param", async () => {
  const { mock, calls } = makeFetchMock({ events: [], next_cursor: null })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({ limit: 25 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), "25")
})

test("listActivity omits limit when not set", async () => {
  const { mock, calls } = makeFetchMock({ events: [], next_cursor: null })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({})

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), null)
})

test("listActivity returns event list with next_cursor", async () => {
  const events = [
    {
      id: "fe-1",
      type: "finding.created",
      occurred_at: "2026-01-15T12:00:00+00:00",
      actor: "alice@example.com",
      repo_id: "acme-org/api",
      summary: "New finding: CVE-2024-12345",
      payload: { finding_id: 42 },
    },
  ]
  const { mock } = makeFetchMock({ events, next_cursor: "cursor-xyz" })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  const result = await listActivity({})

  assert.equal(result.events.length, 1)
  assert.equal(result.events[0].id, "fe-1")
  assert.equal(result.events[0].type, "finding.created")
  assert.equal(result.next_cursor, "cursor-xyz")
})

test("listActivity throws on non-ok response", async () => {
  const { mock } = makeFetchMock({ detail: "Unauthorized" }, 401)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await assert.rejects(listActivity({}), /activity-api: 401/)
})

// ---------------------------------------------------------------------------
// listActivityTypes
// ---------------------------------------------------------------------------

test("listActivityTypes returns array of strings", async () => {
  const types = ["finding.created", "scan.completed", "integration.connected"]
  const { mock } = makeFetchMock({ types })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivityTypes } = await loadModule()
  const result = await listActivityTypes()

  assert.deepEqual(result, types)
})

test("listActivityTypes calls correct endpoint", async () => {
  const { mock, calls } = makeFetchMock({ types: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivityTypes } = await loadModule()
  await listActivityTypes()

  assert.equal(calls[0].url, "/api/v1/activity/types")
})

test("listActivityTypes throws on non-ok response", async () => {
  const { mock } = makeFetchMock({ detail: "error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivityTypes } = await loadModule()
  await assert.rejects(listActivityTypes(), /activity-api: 500/)
})

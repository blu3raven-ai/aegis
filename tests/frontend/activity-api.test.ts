import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// activity-api uses GraphQL by design — events is a service-side union across
// findings + finding_events + scan_runs, which CLAUDE.md flags as a GQL fit.
// Tests assert the GraphQL request shape and response unwrapping.
// ---------------------------------------------------------------------------

interface FetchCall { url: string; body: { operationName: string; variables: Record<string, unknown> } }

function makeFetchMock(payload: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({
      url: input.toString(),
      body: JSON.parse(init?.body as string) as FetchCall["body"],
    })
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

function activityResponse(events: unknown[], nextCursor: string | null) {
  return { data: { history: { events: { events, nextCursor } } } }
}

async function loadModule() {
  return import("../../frontend/lib/client/activity-api.ts")
}

// ---------------------------------------------------------------------------
// listActivity GraphQL request shape
// ---------------------------------------------------------------------------

test("listActivity POSTs to /api/v1/graphql with operationName Activity", async () => {
  const { mock, calls } = makeFetchMock(activityResponse([], null))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({})

  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(calls[0].body.operationName, "Activity")
})

test("listActivity passes types variable as array when set", async () => {
  const { mock, calls } = makeFetchMock(activityResponse([], null))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({ types: ["finding.created", "scan.completed"] })

  assert.deepEqual(calls[0].body.variables.types, ["finding.created", "scan.completed"])
})

test("listActivity sends null types when omitted", async () => {
  const { mock, calls } = makeFetchMock(activityResponse([], null))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({})

  assert.equal(calls[0].body.variables.types, null)
})

test("listActivity maps repo_id to repoId variable", async () => {
  const { mock, calls } = makeFetchMock(activityResponse([], null))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({ repo_id: "acme-org/api" })

  assert.equal(calls[0].body.variables.repoId, "acme-org/api")
})

test("listActivity forwards since/until/limit/cursor variables", async () => {
  const { mock, calls } = makeFetchMock(activityResponse([], null))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await listActivity({
    since: "2026-01-01T00:00:00Z",
    until: "2026-01-31T23:59:59Z",
    limit: 25,
    cursor: "abc123",
  })

  assert.equal(calls[0].body.variables.since, "2026-01-01T00:00:00Z")
  assert.equal(calls[0].body.variables.until, "2026-01-31T23:59:59Z")
  assert.equal(calls[0].body.variables.limit, 25)
  assert.equal(calls[0].body.variables.cursor, "abc123")
})

test("listActivity unwraps response and converts camelCase to snake_case", async () => {
  const payload = activityResponse(
    [
      {
        id: "fe-1",
        type: "finding.created",
        occurredAt: "2026-01-15T12:00:00+00:00",
        actor: "alice@example.com",
        repoId: "acme-org/api",
        summary: "New finding: CVE-2024-12345",
        payloadJson: JSON.stringify({ finding_id: 42 }),
      },
    ],
    "cursor-xyz",
  )
  const { mock } = makeFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  const result = await listActivity({})

  assert.equal(result.events.length, 1)
  assert.equal(result.events[0].id, "fe-1")
  assert.equal(result.events[0].occurred_at, "2026-01-15T12:00:00+00:00")
  assert.equal(result.events[0].repo_id, "acme-org/api")
  assert.deepEqual(result.events[0].payload, { finding_id: 42 })
  assert.equal(result.next_cursor, "cursor-xyz")
})

test("listActivity falls back to empty payload object on invalid JSON", async () => {
  const payload = activityResponse(
    [
      {
        id: "fe-2",
        type: "scan.completed",
        occurredAt: "2026-01-15T12:00:00+00:00",
        actor: null,
        repoId: null,
        summary: "Scan complete",
        payloadJson: "not json",
      },
    ],
    null,
  )
  const { mock } = makeFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  const result = await listActivity({})

  assert.deepEqual(result.events[0].payload, {})
})

test("listActivity throws when GraphQL response has errors", async () => {
  const payload = { errors: [{ message: "boom" }] }
  const { mock } = makeFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadModule()
  await assert.rejects(listActivity({}), /boom/)
})

// ---------------------------------------------------------------------------
// listActivityTypes
// ---------------------------------------------------------------------------

test("listActivityTypes uses operationName ActivityTypes", async () => {
  const { mock, calls } = makeFetchMock({ data: { history: { types: [] } } })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivityTypes } = await loadModule()
  await listActivityTypes()

  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(calls[0].body.operationName, "ActivityTypes")
})

test("listActivityTypes returns array of strings", async () => {
  const types = ["finding.created", "scan.completed", "integration.connected"]
  const { mock } = makeFetchMock({ data: { history: { types } } })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivityTypes } = await loadModule()
  const result = await listActivityTypes()

  assert.deepEqual(result, types)
})

test("listActivityTypes throws when GraphQL response has errors", async () => {
  const { mock } = makeFetchMock({ errors: [{ message: "denied" }] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivityTypes } = await loadModule()
  await assert.rejects(listActivityTypes(), /denied/)
})

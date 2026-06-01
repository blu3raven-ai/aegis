import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Fleet page data-flow tests — validates the API client behaviour that the
// page and RunnersTable component depend on for rendering and auto-refresh.
// ---------------------------------------------------------------------------

interface FetchCall { url: string; callIndex: number }

function makeSequentialFetchMock(responses: unknown[]) {
  const calls: FetchCall[] = []
  let index = 0
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    const body = responses[Math.min(index, responses.length - 1)]
    calls.push({ url: input.toString(), callIndex: index })
    index++
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  let index = 0
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    calls.push({ url: input.toString(), callIndex: index++ })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadFleetApi() {
  return import("../../lib/client/fleet-api.ts")
}

const HEALTHY = {
  agent_id: "runner-abc",
  hostname: "node-01",
  scanner_types: ["dependencies", "sast"],
  in_flight_jobs: 2,
  processed_total: 1450,
  last_heartbeat_at: "2026-05-31T10:00:00Z",
  seconds_since_heartbeat: 5,
  status: "healthy" as const,
}

const DEGRADED = {
  agent_id: "runner-xyz",
  hostname: "node-02",
  scanner_types: ["secrets"],
  in_flight_jobs: 0,
  processed_total: 800,
  last_heartbeat_at: "2026-05-31T09:58:30Z",
  seconds_since_heartbeat: 90,
  status: "degraded" as const,
}

// ---------------------------------------------------------------------------
// Initial page load — runners list
// ---------------------------------------------------------------------------

test("page load: listRunners returns runners for table render", async () => {
  const { mock, calls } = makeFetchMock({ runners: [HEALTHY, DEGRADED] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()
  const runners = await listRunners()

  assert.equal(calls.length, 1)
  assert.equal(runners.length, 2)
})

test("page load: empty fleet shows no runners", async () => {
  const { mock } = makeFetchMock({ runners: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()
  const runners = await listRunners()
  assert.equal(runners.length, 0)
})

// ---------------------------------------------------------------------------
// Summary counts — derived from runners array
// ---------------------------------------------------------------------------

test("summary: counts healthy, degraded, dead runners correctly", async () => {
  const dead = { ...HEALTHY, agent_id: "runner-dead", status: "dead" as const }
  const { mock } = makeFetchMock({ runners: [HEALTHY, DEGRADED, dead] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()
  const runners = await listRunners()

  const healthy = runners.filter((r) => r.status === "healthy").length
  const degraded = runners.filter((r) => r.status === "degraded").length
  const dead_count = runners.filter((r) => r.status === "dead").length

  assert.equal(healthy, 1)
  assert.equal(degraded, 1)
  assert.equal(dead_count, 1)
  assert.equal(runners.length, 3)
})

test("summary: all-healthy fleet shows 0 degraded and 0 dead", async () => {
  const runners = [HEALTHY, { ...HEALTHY, agent_id: "runner-2" }]
  const { mock } = makeFetchMock({ runners })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()
  const result = await listRunners()

  assert.equal(result.filter((r) => r.status === "degraded").length, 0)
  assert.equal(result.filter((r) => r.status === "dead").length, 0)
})

// ---------------------------------------------------------------------------
// Auto-refresh simulation — multiple sequential fetches
// ---------------------------------------------------------------------------

test("auto-refresh: second fetch picks up new runner", async () => {
  const second = { ...HEALTHY, agent_id: "runner-new" }
  const { mock, calls } = makeSequentialFetchMock([
    { runners: [HEALTHY] },
    { runners: [HEALTHY, second] },
  ])
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()

  const first = await listRunners()
  assert.equal(first.length, 1)

  const refreshed = await listRunners()
  assert.equal(refreshed.length, 2)
  assert.equal(calls.length, 2)
})

test("auto-refresh: status can change between polls", async () => {
  const degradedNow = { ...HEALTHY, status: "degraded" as const, seconds_since_heartbeat: 70 }
  const { mock } = makeSequentialFetchMock([
    { runners: [HEALTHY] },
    { runners: [degradedNow] },
  ])
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()

  const [before] = await listRunners()
  assert.equal(before.status, "healthy")

  const [after] = await listRunners()
  assert.equal(after.status, "degraded")
})

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

test("empty state: no runners triggers empty fleet condition", async () => {
  const { mock } = makeFetchMock({ runners: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()
  const runners = await listRunners()
  // The page/component renders EmptyFleetState when this is empty
  assert.equal(runners.length === 0, true)
})

// ---------------------------------------------------------------------------
// Scanner types shape
// ---------------------------------------------------------------------------

test("runner scanner_types is always an array", async () => {
  const { mock } = makeFetchMock({ runners: [HEALTHY] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadFleetApi()
  const [runner] = await listRunners()
  assert.ok(Array.isArray(runner.scanner_types))
})

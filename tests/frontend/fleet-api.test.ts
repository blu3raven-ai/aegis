import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for the fleet API client (lib/client/fleet-api.ts)
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
  return import("../../lib/client/fleet-api.ts")
}

const SAMPLE_RUNNER = {
  agent_id: "runner-abc",
  hostname: "node-01",
  scanner_types: ["dependencies", "sast"],
  in_flight_jobs: 2,
  processed_total: 1450,
  last_heartbeat_at: "2026-05-31T10:00:00Z",
  seconds_since_heartbeat: 5,
  status: "healthy" as const,
}

// ---------------------------------------------------------------------------
// listRunners
// ---------------------------------------------------------------------------

test("listRunners fetches /api/v1/fleet/runners", async () => {
  const { mock, calls } = makeFetchMock({ runners: [SAMPLE_RUNNER] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  const result = await listRunners()

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/fleet/runners")
  assert.equal(result.length, 1)
})

test("listRunners returns parsed runner with all fields", async () => {
  const { mock } = makeFetchMock({ runners: [SAMPLE_RUNNER] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  const [runner] = await listRunners()

  assert.equal(runner.agent_id, "runner-abc")
  assert.equal(runner.hostname, "node-01")
  assert.deepEqual(runner.scanner_types, ["dependencies", "sast"])
  assert.equal(runner.in_flight_jobs, 2)
  assert.equal(runner.processed_total, 1450)
  assert.equal(runner.status, "healthy")
  assert.equal(typeof runner.seconds_since_heartbeat, "number")
})

test("listRunners returns empty array when runners is missing", async () => {
  const { mock } = makeFetchMock({})
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  const result = await listRunners()
  assert.deepEqual(result, [])
})

test("listRunners returns empty array when runners is empty", async () => {
  const { mock } = makeFetchMock({ runners: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  const result = await listRunners()
  assert.deepEqual(result, [])
})

test("listRunners throws on non-ok response", async () => {
  const { mock } = makeFetchMock({ detail: "Unauthorized" }, 401)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  await assert.rejects(() => listRunners(), /fleet-api: 401/)
})

test("listRunners throws on 500 response", async () => {
  const { mock } = makeFetchMock({ detail: "Internal server error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  await assert.rejects(() => listRunners(), /fleet-api: 500/)
})

// ---------------------------------------------------------------------------
// Status field values
// ---------------------------------------------------------------------------

test("listRunners preserves status: degraded", async () => {
  const degraded = { ...SAMPLE_RUNNER, status: "degraded" as const, seconds_since_heartbeat: 80 }
  const { mock } = makeFetchMock({ runners: [degraded] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  const [r] = await listRunners()
  assert.equal(r.status, "degraded")
})

test("listRunners preserves status: dead", async () => {
  const dead = { ...SAMPLE_RUNNER, status: "dead" as const, seconds_since_heartbeat: 150 }
  const { mock } = makeFetchMock({ runners: [dead] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  const [r] = await listRunners()
  assert.equal(r.status, "dead")
})

// ---------------------------------------------------------------------------
// Multiple runners
// ---------------------------------------------------------------------------

test("listRunners handles multiple runners", async () => {
  const runners = [
    SAMPLE_RUNNER,
    { ...SAMPLE_RUNNER, agent_id: "runner-xyz", status: "degraded" as const },
  ]
  const { mock } = makeFetchMock({ runners })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRunners } = await loadModule()
  const result = await listRunners()
  assert.equal(result.length, 2)
  assert.equal(result[0].agent_id, "runner-abc")
  assert.equal(result[1].agent_id, "runner-xyz")
})

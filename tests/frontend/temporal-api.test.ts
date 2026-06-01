import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock that records the URL and returns a preset body
// ---------------------------------------------------------------------------

interface FetchCall { url: string; body: unknown }

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []

  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    const url = input.toString()
    calls.push({ url, body })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

// ---------------------------------------------------------------------------
// We import the module functions after wiring up a global fetch mock so that
// the dynamic import picks up the patched global.
// ---------------------------------------------------------------------------

async function loadModule() {
  // Node < 22 resolves path aliases differently; use the real filesystem path.
  const mod = await import("../../lib/client/temporal-api.ts")
  return mod
}

// ---------------------------------------------------------------------------
// fetchTemporalSeries
// ---------------------------------------------------------------------------

test("fetchTemporalSeries builds URL with required params", async () => {
  const responseBody = { series: [{ bucket_start: "2026-05-01T00:00:00Z", value: 5, dimension: { severity: "high" } }] }
  const { mock, calls } = makeFetchMock(responseBody)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadModule()
  const result = await fetchTemporalSeries({ metric: "findings_introduced", org_id: "example-org" })

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/temporal/series")
  assert.equal(url.searchParams.get("metric"), "findings_introduced")
  assert.equal(url.searchParams.get("org_id"), "example-org")
  assert.equal(result.length, 1)
  assert.equal(result[0].value, 5)
})

test("fetchTemporalSeries forwards optional params", async () => {
  const { mock, calls } = makeFetchMock({ series: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadModule()
  await fetchTemporalSeries({
    metric: "findings_introduced",
    org_id: "example-org",
    bucket_size: "1w",
    since_days: 90,
    severity: "critical",
    scanner_type: "sca",
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("bucket_size"), "1w")
  assert.equal(url.searchParams.get("since_days"), "90")
  assert.equal(url.searchParams.get("severity"), "critical")
  assert.equal(url.searchParams.get("scanner_type"), "sca")
})

test("fetchTemporalSeries accepts bare array response", async () => {
  const pts = [{ bucket_start: "2026-05-01T00:00:00Z", value: 3, dimension: {} }]
  const { mock } = makeFetchMock(pts)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadModule()
  const result = await fetchTemporalSeries({ metric: "findings_introduced", org_id: "example-org" })
  assert.equal(result.length, 1)
})

test("fetchTemporalSeries throws on non-OK response", async () => {
  const { mock } = makeFetchMock({ detail: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadModule()
  await assert.rejects(
    () => fetchTemporalSeries({ metric: "x", org_id: "example-org" }),
    /temporal-api: 404/,
  )
})

// ---------------------------------------------------------------------------
// fetchTopAuthors
// ---------------------------------------------------------------------------

test("fetchTopAuthors builds URL with required params", async () => {
  const responseBody = {
    org_id: "example-org",
    since_days: 30,
    authors: [
      { author: "alice", total: 10, breakdown: { critical: 2, high: 3, medium: 4, low: 1 } },
    ],
  }
  const { mock, calls } = makeFetchMock(responseBody)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTopAuthors } = await loadModule()
  const result = await fetchTopAuthors({ org_id: "example-org" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/temporal/top-authors")
  assert.equal(url.searchParams.get("org_id"), "example-org")
  assert.equal(result.length, 1)
  assert.equal(result[0].author, "alice")
  assert.equal(result[0].total, 10)
  assert.equal(result[0].by_severity.critical, 2)
})

test("fetchTopAuthors forwards since_days and limit", async () => {
  const { mock, calls } = makeFetchMock({ org_id: "x", since_days: 7, authors: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTopAuthors } = await loadModule()
  await fetchTopAuthors({ org_id: "example-org", since_days: 7, limit: 5 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("since_days"), "7")
  assert.equal(url.searchParams.get("limit"), "5")
})

// ---------------------------------------------------------------------------
// fetchMttr
// ---------------------------------------------------------------------------

test("fetchMttr builds URL and maps group key", async () => {
  const responseBody = {
    org_id: "example-org",
    since_days: 30,
    group_by: "scanner_type",
    mttr: [
      { scanner_type: "sca", avg_ms: 86400000, sample_count: 12 },
      { scanner_type: "sast", avg_ms: 43200000, sample_count: 8 },
    ],
  }
  const { mock, calls } = makeFetchMock(responseBody)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchMttr } = await loadModule()
  const result = await fetchMttr({ org_id: "example-org" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/temporal/mttr")
  assert.equal(url.searchParams.get("org_id"), "example-org")
  assert.equal(result.length, 2)
  assert.equal(result[0].group, "sca")
  assert.equal(result[0].avg_ms, 86400000)
  assert.equal(result[0].sample_count, 12)
})

test("fetchMttr maps severity group_by correctly", async () => {
  const responseBody = {
    org_id: "example-org",
    since_days: 30,
    group_by: "severity",
    mttr: [{ severity: "critical", avg_ms: 3600000, sample_count: 3 }],
  }
  const { mock } = makeFetchMock(responseBody)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchMttr } = await loadModule()
  const result = await fetchMttr({ org_id: "example-org", group_by: "severity" })
  assert.equal(result[0].group, "critical")
})

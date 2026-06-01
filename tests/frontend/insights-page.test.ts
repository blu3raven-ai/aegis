import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for InsightsHeader filter chip state and temporal-api integration
// ---------------------------------------------------------------------------

// Re-test the temporal API URL construction with different window/severity
// combinations to simulate what the page does when filters change.

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

async function loadTemporalApi() {
  return import("../../lib/client/temporal-api.ts")
}

// ---------------------------------------------------------------------------
// Filter chip → URL param mapping
// ---------------------------------------------------------------------------

test("7d window maps to bucket_size 1h", async () => {
  const { mock, calls } = makeFetchMock({ series: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadTemporalApi()
  await fetchTemporalSeries({
    metric: "findings_introduced",
    org_id: "example-org",
    bucket_size: "1h",   // page sends 1h for ≤7d
    since_days: 7,
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("bucket_size"), "1h")
  assert.equal(url.searchParams.get("since_days"), "7")
})

test("30d window maps to bucket_size 1d", async () => {
  const { mock, calls } = makeFetchMock({ series: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadTemporalApi()
  await fetchTemporalSeries({
    metric: "findings_introduced",
    org_id: "example-org",
    bucket_size: "1d",
    since_days: 30,
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("bucket_size"), "1d")
  assert.equal(url.searchParams.get("since_days"), "30")
})

test("severity filter is passed through when not 'all'", async () => {
  const { mock, calls } = makeFetchMock({ series: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadTemporalApi()
  await fetchTemporalSeries({
    metric: "findings_introduced",
    org_id: "example-org",
    since_days: 30,
    severity: "critical",
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("severity"), "critical")
})

test("severity 'all' means no severity param in URL", async () => {
  const { mock, calls } = makeFetchMock({ series: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadTemporalApi()
  // When severity === 'all', page passes severity: undefined
  await fetchTemporalSeries({
    metric: "findings_introduced",
    org_id: "example-org",
    since_days: 30,
    severity: undefined,
  })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.has("severity"), false)
})

// ---------------------------------------------------------------------------
// Empty / error state data shapes
// ---------------------------------------------------------------------------

test("empty series produces zero-length array", async () => {
  const { mock } = makeFetchMock({ series: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadTemporalApi()
  const result = await fetchTemporalSeries({ metric: "findings_introduced", org_id: "example-org" })
  assert.equal(result.length, 0)
})

test("empty authors array returned on no data", async () => {
  const { mock } = makeFetchMock({ org_id: "example-org", since_days: 30, authors: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTopAuthors } = await loadTemporalApi()
  const result = await fetchTopAuthors({ org_id: "example-org" })
  assert.equal(result.length, 0)
})

test("error state: fetchTemporalSeries rejects on 500", async () => {
  const { mock } = makeFetchMock({ detail: "server error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTemporalSeries } = await loadTemporalApi()
  await assert.rejects(
    () => fetchTemporalSeries({ metric: "findings_introduced", org_id: "example-org" }),
    /temporal-api: 500/,
  )
})

test("error state: fetchTopAuthors rejects on 500", async () => {
  const { mock } = makeFetchMock({ detail: "server error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTopAuthors } = await loadTemporalApi()
  await assert.rejects(
    () => fetchTopAuthors({ org_id: "example-org" }),
    /temporal-api: 500/,
  )
})

test("error state: fetchMttr rejects on 500", async () => {
  const { mock } = makeFetchMock({ detail: "server error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchMttr } = await loadTemporalApi()
  await assert.rejects(
    () => fetchMttr({ org_id: "example-org" }),
    /temporal-api: 500/,
  )
})

// ---------------------------------------------------------------------------
// TopAuthor severity breakdown defaults to 0 for missing keys
// ---------------------------------------------------------------------------

test("fetchTopAuthors fills missing severity breakdown with zeros", async () => {
  const responseBody = {
    org_id: "example-org",
    since_days: 30,
    authors: [
      { author: "bob", total: 5, breakdown: { high: 5 } }, // no critical/medium/low
    ],
  }
  const { mock } = makeFetchMock(responseBody)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchTopAuthors } = await loadTemporalApi()
  const result = await fetchTopAuthors({ org_id: "example-org" })
  assert.equal(result[0].by_severity.critical, 0)
  assert.equal(result[0].by_severity.high, 5)
  assert.equal(result[0].by_severity.medium, 0)
  assert.equal(result[0].by_severity.low, 0)
})

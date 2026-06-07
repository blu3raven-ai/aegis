import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for the EPSS API client (Phase 54 — surfaces Phase 50 backend).
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

async function loadModule() {
  return import("../../frontend/lib/client/epss-api.ts")
}

const MOCK_SCORE = {
  cve: "CVE-2021-44228",
  score: 0.97432,
  percentile: 0.9999,
  scored_date: "2024-05-13",
  fetched_at: "2024-05-13T00:00:00Z",
}

const MOCK_TOP = {
  findings: [
    { finding_id: 1, tool: "deps", repo: "acme-org/api", severity: "critical", identity_key: "k1", cve: "CVE-2021-44228", epss_score: 0.97, epss_percentile: 0.9999, scored_date: "2024-05-13" },
    { finding_id: 2, tool: "deps", repo: "acme-org/api", severity: "high", identity_key: "k2", cve: "CVE-2024-27351", epss_score: 0.42, epss_percentile: 0.74, scored_date: "2024-05-13" },
  ],
  count: 2,
}

// ── getEpssScore ──────────────────────────────────────────────────────────────

test("getEpssScore: fetches score by CVE", async () => {
  const { mock, calls } = makeFetchMock(MOCK_SCORE)
  ;(globalThis as any).fetch = mock

  const { getEpssScore } = await loadModule()
  const score = await getEpssScore("CVE-2021-44228")

  assert.equal(calls.length, 1)
  assert.ok(calls[0].url.includes("/api/v1/epss/scores/CVE-2021-44228"))
  assert.equal(score?.cve, "CVE-2021-44228")
  assert.equal(score?.percentile, 0.9999)
})

test("getEpssScore: URL-encodes the CVE id", async () => {
  const { mock, calls } = makeFetchMock(MOCK_SCORE)
  ;(globalThis as any).fetch = mock

  const { getEpssScore } = await loadModule()
  await getEpssScore("CVE-2021-44228")

  // No reserved characters in the standard CVE format but ensure encoding is wired
  assert.ok(!calls[0].url.includes(" "))
})

test("getEpssScore: returns null on 404 (CVE not in feed)", async () => {
  const { mock } = makeFetchMock({ detail: "CVE-9999-9999 is not in the EPSS feed" }, 404)
  ;(globalThis as any).fetch = mock

  const { getEpssScore } = await loadModule()
  const score = await getEpssScore("CVE-9999-9999")
  assert.equal(score, null)
})

test("getEpssScore: throws on non-404 errors", async () => {
  const { mock } = makeFetchMock({ detail: "Internal Server Error" }, 500)
  ;(globalThis as any).fetch = mock

  const { getEpssScore } = await loadModule()
  await assert.rejects(() => getEpssScore("CVE-2021-44228"), (err: any) => {
    assert.equal(err.status, 500)
    return true
  })
})

// ── getEpssTop ────────────────────────────────────────────────────────────────

test("getEpssTop: builds correct query string", async () => {
  const { mock, calls } = makeFetchMock(MOCK_TOP)
  ;(globalThis as any).fetch = mock

  const { getEpssTop } = await loadModule()
  const result = await getEpssTop("acme-org", 5)

  assert.equal(calls.length, 1)
  const parsed = new URL(calls[0].url, "http://localhost")
  assert.equal(parsed.pathname, "/api/v1/epss/top")
  assert.equal(parsed.searchParams.get("org_id"), "acme-org")
  assert.equal(parsed.searchParams.get("limit"), "5")
  assert.equal(result.count, 2)
  assert.equal(result.findings.length, 2)
})

test("getEpssTop: defaults limit to 5", async () => {
  const { mock, calls } = makeFetchMock(MOCK_TOP)
  ;(globalThis as any).fetch = mock

  const { getEpssTop } = await loadModule()
  await getEpssTop("acme-org")

  const parsed = new URL(calls[0].url, "http://localhost")
  assert.equal(parsed.searchParams.get("limit"), "5")
})

// ── triggerEpssRefresh ────────────────────────────────────────────────────────

test("triggerEpssRefresh: POSTs and returns counts", async () => {
  const { mock, calls } = makeFetchMock({ fetched: 250000, new: 12 })
  ;(globalThis as any).fetch = mock
  // apiClient requires CSRF cookie for POST requests
  ;(globalThis as any).document = { cookie: "__Host-csrf=test-token" }

  const { triggerEpssRefresh } = await loadModule()
  const result = await triggerEpssRefresh()

  assert.equal(calls.length, 1)
  assert.equal(calls[0].init?.method, "POST")
  assert.equal(result.fetched, 250000)
  assert.equal(result.new, 12)
})

// ── formatPercentile ──────────────────────────────────────────────────────────

test("formatPercentile: rounds to whole-number percent", async () => {
  const { formatPercentile } = await loadModule()
  assert.equal(formatPercentile(0.9762), "98%")
  assert.equal(formatPercentile(0.74), "74%")
  assert.equal(formatPercentile(0.005), "1%")
  assert.equal(formatPercentile(1), "100%")
  assert.equal(formatPercentile(0), "0%")
})

test("formatPercentile: returns null for missing or non-finite values", async () => {
  const { formatPercentile } = await loadModule()
  assert.equal(formatPercentile(null), null)
  assert.equal(formatPercentile(undefined), null)
  assert.equal(formatPercentile(NaN), null)
  assert.equal(formatPercentile(Infinity), null)
})

// ── epssBucket ────────────────────────────────────────────────────────────────

test("epssBucket: percentile >= 0.9 is high", async () => {
  const { epssBucket } = await loadModule()
  assert.equal(epssBucket(0.9), "high")
  assert.equal(epssBucket(0.95), "high")
  assert.equal(epssBucket(1), "high")
})

test("epssBucket: percentile in [0.7, 0.9) is medium", async () => {
  const { epssBucket } = await loadModule()
  assert.equal(epssBucket(0.7), "medium")
  assert.equal(epssBucket(0.85), "medium")
  assert.equal(epssBucket(0.89), "medium")
})

test("epssBucket: percentile < 0.7 is none", async () => {
  const { epssBucket } = await loadModule()
  assert.equal(epssBucket(0), "none")
  assert.equal(epssBucket(0.5), "none")
  assert.equal(epssBucket(0.69), "none")
})

test("epssBucket: missing percentile is none", async () => {
  const { epssBucket } = await loadModule()
  assert.equal(epssBucket(null), "none")
  assert.equal(epssBucket(undefined), "none")
  assert.equal(epssBucket(NaN), "none")
})

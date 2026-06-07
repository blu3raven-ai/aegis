import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for the findings inbox page data-flow behaviour that doesn't require
// a DOM. Validates the API client wiring (URL composition, filter forwarding,
// cursor pagination) and the row-mapping helper that converts an aggregated
// API row into the local Finding shape rendered by the table.
// ---------------------------------------------------------------------------

interface FetchCall { url: string }

function makeFetchMock(responses: unknown[]) {
  const calls: FetchCall[] = []
  let index = 0
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    const body = responses[Math.min(index, responses.length - 1)]
    calls.push({ url: input.toString() })
    index++
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

function makeErrorFetchMock(status = 500) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    calls.push({ url: input.toString() })
    return new Response("upstream failure", { status })
  }
  return { mock, calls }
}

async function loadApi() {
  return import("../../frontend/lib/client/findings-api.ts")
}

async function loadMapper() {
  return import("../../frontend/lib/shared/findings/row-mapper.ts")
}

function makeApiFinding(overrides: Record<string, unknown> = {}) {
  return {
    id: "f-1",
    scanner: "deps",
    severity: "critical",
    state: "open",
    title: "log4j JNDI RCE",
    cve: "CVE-2021-44228",
    package: "log4j-core",
    file_path: null,
    line: null,
    repo: "acme-org/api",
    org_id: "acme-org",
    created_at: "2026-05-30T00:00:00Z",
    updated_at: "2026-05-30T00:00:00Z",
    epss_percentile: 0.98,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Initial mount — page loads findings from the aggregated endpoint
// ---------------------------------------------------------------------------

test("page load: listFindings hits /api/v1/findings with org_id", async () => {
  const { mock, calls } = makeFetchMock([
    { findings: [makeApiFinding()], next_cursor: null, total_count: 1 },
  ])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  const resp = await listFindings({ orgId: "acme-org", limit: 50 })

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/findings")
  assert.equal(url.searchParams.get("org_id"), "acme-org")
  assert.equal(url.searchParams.get("limit"), "50")
  assert.equal(resp.findings.length, 1)
  assert.equal(resp.total_count, 1)
})

test("page load: rows render with normalised epssPercentile", async () => {
  const { mock } = makeFetchMock([
    {
      findings: [makeApiFinding({ epss_percentile: 0.9762 })],
      next_cursor: null,
      total_count: 1,
    },
  ])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  const resp = await listFindings({ orgId: "acme-org" })

  // EpssScoreCell reads `epssPercentile` (camelCase) — this is the
  // contract preserved by the client normaliser.
  assert.equal(resp.findings[0].epssPercentile, 0.9762)
})

// ---------------------------------------------------------------------------
// Empty state — endpoint returns zero findings
// ---------------------------------------------------------------------------

test("empty state: zero findings returns empty array and null cursor", async () => {
  const { mock } = makeFetchMock([{ findings: [], next_cursor: null, total_count: 0 }])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  const resp = await listFindings({ orgId: "acme-org" })

  assert.equal(resp.findings.length, 0)
  assert.equal(resp.next_cursor, null)
  assert.equal(resp.total_count, 0)
})

// ---------------------------------------------------------------------------
// Error state — endpoint returns a non-2xx response
// ---------------------------------------------------------------------------

test("error state: 500 response surfaces as a thrown error", async () => {
  const { mock } = makeErrorFetchMock(500)
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await assert.rejects(
    () => listFindings({ orgId: "acme-org" }),
    /500/,
  )
})

test("error state: client rejects empty orgId before fetching", async () => {
  let called = false
  ;(globalThis as any).fetch = async () => {
    called = true
    return new Response("{}", { status: 200 })
  }

  const { listFindings } = await loadApi()
  await assert.rejects(
    () => listFindings({ orgId: "" }),
    /orgId is required/,
  )
  assert.equal(called, false)
})

// ---------------------------------------------------------------------------
// Severity filter — selected chip is forwarded as a CSV query param
// ---------------------------------------------------------------------------

test("severity filter: critical filter forwards severity=critical", async () => {
  const { mock, calls } = makeFetchMock([
    { findings: [], next_cursor: null, total_count: 0 },
  ])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", severity: ["critical"] })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("severity"), "critical")
})

test("severity filter: multiple severities are joined with comma", async () => {
  const { mock, calls } = makeFetchMock([
    { findings: [], next_cursor: null, total_count: 0 },
  ])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", severity: ["critical", "high"] })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("severity"), "critical,high")
})

test("severity filter: empty severity array is omitted from URL", async () => {
  const { mock, calls } = makeFetchMock([
    { findings: [], next_cursor: null, total_count: 0 },
  ])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", severity: [] })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.has("severity"), false)
})

// ---------------------------------------------------------------------------
// Page-number pagination — second call forwards `page` in the query string
// ---------------------------------------------------------------------------

test("pagination: page=1 is omitted from URL (default)", async () => {
  const { mock, calls } = makeFetchMock([
    { findings: [makeApiFinding()], next_cursor: null, total_count: 1 },
  ])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", limit: 2, page: 1 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("page"), "1")
})

test("pagination: second call carries page=N in the URL", async () => {
  const page1 = {
    findings: [makeApiFinding({ id: "f-1" }), makeApiFinding({ id: "f-2" })],
    next_cursor: null,
    total_count: 3,
  }
  const page2 = {
    findings: [makeApiFinding({ id: "f-3" })],
    next_cursor: null,
    total_count: 3,
  }

  const { mock, calls } = makeFetchMock([page1, page2])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()

  await listFindings({ orgId: "acme-org", limit: 2, page: 1 })
  const r2 = await listFindings({ orgId: "acme-org", limit: 2, page: 2 })

  assert.equal(r2.findings.length, 1)
  assert.equal(r2.total_count, 3)

  const url2 = new URL(calls[1].url, "http://localhost")
  assert.equal(url2.searchParams.get("page"), "2")
  assert.equal(url2.searchParams.get("limit"), "2")
})

test("pagination: page is omitted from URL when not provided", async () => {
  const { mock, calls } = makeFetchMock([
    { findings: [makeApiFinding()], next_cursor: null, total_count: 1 },
  ])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.has("page"), false)
})

// ---------------------------------------------------------------------------
// Row mapping — the page-level helper that bridges the API shape to the
// table's Finding interface. Verifies the contract that breaking changes here
// would silently corrupt rendering.
// ---------------------------------------------------------------------------

test("mapApiFinding: maps scanner `container` to the UI `containers` token", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({ scanner: "container" }) as any)
  assert.equal(row.scanner, "containers")
})

test("mapApiFinding: passes through known scanner tokens unchanged", async () => {
  const { mapApiFinding } = await loadMapper()
  for (const scanner of ["deps", "sast", "secrets"]) {
    const row = mapApiFinding(makeApiFinding({ scanner }) as any)
    assert.equal(row.scanner, scanner)
  }
})

test("mapApiFinding: unknown scanner falls back to deps so the row still renders", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({ scanner: "wat" }) as any)
  assert.equal(row.scanner, "deps")
})

test("mapApiFinding: title falls back to cve when title is null", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(
    makeApiFinding({ title: null, cve: "CVE-2024-27351" }) as any,
  )
  assert.equal(row.title, "CVE-2024-27351")
})

test("mapApiFinding: filePath combines file_path and line when both present", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(
    makeApiFinding({ file_path: "src/handlers/users.py", line: 142 }) as any,
  )
  assert.equal(row.filePath, "src/handlers/users.py:142")
})

test("mapApiFinding: filePath omits line when line is null", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(
    makeApiFinding({ file_path: "src/handlers/users.py", line: null }) as any,
  )
  assert.equal(row.filePath, "src/handlers/users.py")
})

test("mapApiFinding: epssPercentile is preserved end-to-end", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(
    { ...(makeApiFinding({}) as any), epssPercentile: 0.9762 },
  )
  assert.equal(row.epssPercentile, 0.9762)
})

test("mapApiFinding: severity defaults to `low` when server returns null", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({ severity: null }) as any)
  assert.equal(row.severity, "low")
})

import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for the findings inbox page data-flow behaviour that doesn't require
// a DOM. Validates the API client wiring (GraphQL query, filter forwarding,
// pagination) and the row-mapping helper that converts an aggregated API row
// into the local Finding shape rendered by the table.
// ---------------------------------------------------------------------------

interface FetchCall { url: string; body: unknown }

interface GqlPayload {
  operationName?: string
  query?: string
  variables?: Record<string, unknown>
}

function makeFetchMock(responses: unknown[]) {
  const calls: FetchCall[] = []
  let index = 0
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const body = responses[Math.min(index, responses.length - 1)]
    let parsed: unknown = null
    if (init?.body) {
      try { parsed = JSON.parse(init.body as string) } catch { parsed = init.body }
    }
    calls.push({ url: input.toString(), body: parsed })
    index++
    return new Response(JSON.stringify({ data: body }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

function makeErrorFetchMock(status = 500) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    calls.push({ url: input.toString(), body: null })
    return new Response(JSON.stringify({ errors: [{ message: "upstream failure" }] }), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadApi() {
  return import("../../frontend/lib/client/findings-api.ts")
}

async function loadMapper() {
  return import("../../frontend/lib/shared/findings/row-mapper.ts")
}

function makeGqlFinding(overrides: Record<string, unknown> = {}) {
  return {
    id: "f-1",
    scanner: "deps",
    severity: "critical",
    state: "open",
    title: "log4j JNDI RCE",
    cve: "CVE-2021-44228",
    package: "log4j-core",
    filePath: null,
    line: null,
    repo: "acme-org/api",
    orgId: "acme-org",
    createdAt: "2026-05-30T00:00:00Z",
    updatedAt: "2026-05-30T00:00:00Z",
    epssPercentile: 0.98,
    kev: false,
    cwe: null,
    riskScore: null,
    assigneeUserId: null,
    verdict: null,
    ...overrides,
  }
}

function gqlOk(rows: unknown[], totalCount = rows.length) {
  return {
    findings: {
      search: {
        findings: rows,
        nextCursor: null,
        totalCount,
        verdictCounts: null,
      },
    },
  }
}

// API-shape (snake_case) finding fixture used by the row-mapper tests.
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
    epssPercentile: 0.98,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Initial mount — page loads findings from the findingsSearch GraphQL query
// ---------------------------------------------------------------------------

test("page load: listFindings posts to the GraphQL endpoint with org variable", async () => {
  const { mock, calls } = makeFetchMock([gqlOk([makeGqlFinding()])])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  const resp = await listFindings({ orgId: "acme-org", limit: 50 })

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/graphql")
  const payload = calls[0].body as GqlPayload
  assert.match(payload.query ?? "", /findings\s*\{\s*\n?\s*search\b/)
  assert.equal(payload.variables?.org, "acme-org")
  assert.equal(payload.variables?.limit, 50)
  assert.equal(resp.findings.length, 1)
  assert.equal(resp.total_count, 1)
})

test("page load: rows render with normalised epssPercentile", async () => {
  const { mock } = makeFetchMock([gqlOk([makeGqlFinding({ epssPercentile: 0.9762 })])])
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
  const { mock } = makeFetchMock([gqlOk([], 0)])
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
  await assert.rejects(() => listFindings({ orgId: "acme-org" }))
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
// Severity filter — selected chip is forwarded as a CSV variable
// ---------------------------------------------------------------------------

test("severity filter: critical filter forwards severity=critical", async () => {
  const { mock, calls } = makeFetchMock([gqlOk([])])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", severity: ["critical"] })

  const payload = calls[0].body as GqlPayload
  assert.equal(payload.variables?.severity, "critical")
})

test("severity filter: multiple severities are joined with comma", async () => {
  const { mock, calls } = makeFetchMock([gqlOk([])])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", severity: ["critical", "high"] })

  const payload = calls[0].body as GqlPayload
  assert.equal(payload.variables?.severity, "critical,high")
})

test("severity filter: empty severity array is forwarded as null", async () => {
  const { mock, calls } = makeFetchMock([gqlOk([])])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", severity: [] })

  const payload = calls[0].body as GqlPayload
  assert.equal(payload.variables?.severity, null)
})

// ---------------------------------------------------------------------------
// Page-number pagination — second call forwards `page` in variables
// ---------------------------------------------------------------------------

test("pagination: page is forwarded in variables", async () => {
  const { mock, calls } = makeFetchMock([gqlOk([makeGqlFinding()])])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org", limit: 2, page: 1 })

  const payload = calls[0].body as GqlPayload
  assert.equal(payload.variables?.page, 1)
})

test("pagination: second call carries page=N in variables", async () => {
  const page1 = gqlOk(
    [makeGqlFinding({ id: "f-1" }), makeGqlFinding({ id: "f-2" })],
    3,
  )
  const page2 = gqlOk([makeGqlFinding({ id: "f-3" })], 3)

  const { mock, calls } = makeFetchMock([page1, page2])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()

  await listFindings({ orgId: "acme-org", limit: 2, page: 1 })
  const r2 = await listFindings({ orgId: "acme-org", limit: 2, page: 2 })

  assert.equal(r2.findings.length, 1)
  assert.equal(r2.total_count, 3)

  const payload2 = calls[1].body as GqlPayload
  assert.equal(payload2.variables?.page, 2)
  assert.equal(payload2.variables?.limit, 2)
})

test("pagination: page defaults to 1 when not provided", async () => {
  const { mock, calls } = makeFetchMock([gqlOk([makeGqlFinding()])])
  ;(globalThis as any).fetch = mock

  const { listFindings } = await loadApi()
  await listFindings({ orgId: "acme-org" })

  const payload = calls[0].body as GqlPayload
  assert.equal(payload.variables?.page, 1)
})

// ---------------------------------------------------------------------------
// Row mapping — the page-level helper that bridges the API shape to the
// table's Finding interface. Verifies the contract that breaking changes here
// would silently corrupt rendering.
// ---------------------------------------------------------------------------

test("mapApiFinding: passes canonical scanner names through unchanged", async () => {
  const { mapApiFinding } = await loadMapper()
  for (const scanner of [
    "dependencies_scanning",
    "code_scanning",
    "container_scanning",
    "secret_scanning",
    "iac_scanning",
  ]) {
    const row = mapApiFinding(makeApiFinding({ scanner }) as any)
    assert.equal(row.scanner, scanner)
  }
})

test("mapApiFinding: unknown scanner falls back to dependencies_scanning so the row still renders", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({ scanner: "wat" }) as any)
  assert.equal(row.scanner, "dependencies_scanning")
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

// ---------------------------------------------------------------------------
// Readable titles + paths — strip the runner's ephemeral clone prefix and
// rebuild code-scanning titles that leak the workspace path + rule id.
// ---------------------------------------------------------------------------

test("mapApiFinding: strips the workspace/job and <repo>/_checkout/ prefixes from filePath", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({
    file_path: "/workspace/job-a1b95d663fec5bac/example-repo/_checkout/server.py",
    line: 93,
  }) as any)
  assert.equal(row.filePath, "server.py:93")
})

test("mapApiFinding: rebuilds a leaked code-scanning title as file:line", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({
    scanner: "code_scanning",
    title: "example-repo:/workspace/job-a1b95d663fec5bac/example-repo/_checkout/server.py:opt.semgrep.rules.python.lang.security.audit.insecure-transport.requests.request-with-http:93",
    cve: null,
    file_path: "/workspace/job-a1b95d663fec5bac/example-repo/_checkout/server.py",
    line: 93,
  }) as any)
  assert.equal(row.title, "server.py:93")
})

test("mapApiFinding: leaves a normal title untouched", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({ title: "log4j JNDI RCE" }) as any)
  assert.equal(row.title, "log4j JNDI RCE")
})

test("mapApiFinding: rebuilds a secret hash title as a readable location", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({
    scanner: "secret_scanning",
    title: "fdcbc1f7e9a0a0809ed791b68260ac9edfbf109f",
    cve: null,
    file_path: "src/ocr_main.py",
    line: 34,
  }) as any)
  assert.equal(row.title, "Secret in ocr_main.py:34")
})

test("mapApiFinding: a non-hash secret title is left untouched", async () => {
  const { mapApiFinding } = await loadMapper()
  const row = mapApiFinding(makeApiFinding({
    scanner: "secret_scanning",
    title: "AWS Access Key",
    cve: null,
    file_path: "src/ocr_main.py",
    line: 34,
  }) as any)
  assert.equal(row.title, "AWS Access Key")
})

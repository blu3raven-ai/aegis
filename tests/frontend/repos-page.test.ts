import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Page-level integration tests for repos-api.ts
// Validates filter composition, edge cases, and data shape expectations
// that the repos list and detail pages rely on.
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

async function loadApi() {
  return import("../../frontend/lib/client/repos-api.ts")
}

const SUMMARY = {
  repo_id: "acme-org/api",
  org: "acme-org",
  repo: "api",
  last_scanned_sha: "abc1234",
  manifest_set_hash: "hash",
  last_scanned_at: "2026-05-30T10:00:00Z",
  findings_count_by_severity: { critical: 2, high: 1, medium: 0, low: 0 },
  chains_count: 1,
  scanners_with_coverage: ["dependencies"],
  coverage_status: "fresh",
  source_url: null,
}

// ---------------------------------------------------------------------------
// Filter: has_critical + org_id together
// ---------------------------------------------------------------------------

test("listRepos combines multiple filters in query string", async () => {
  const { mock, calls } = makeFetchMock({ repos: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  await listRepos({ org_id: "acme-org", has_critical: true, limit: 25 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("org_id"), "acme-org")
  assert.equal(url.searchParams.get("has_critical"), "true")
  assert.equal(url.searchParams.get("limit"), "25")
})

test("listRepos omits undefined filters from query string", async () => {
  const { mock, calls } = makeFetchMock({ repos: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  await listRepos({})

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.search, "")
})

// ---------------------------------------------------------------------------
// Coverage status values
// ---------------------------------------------------------------------------

test("listRepos returns repos with coverage_status field", async () => {
  const { mock } = makeFetchMock({ repos: [SUMMARY] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  const result = await listRepos()

  assert.ok(["fresh", "stale", "never"].includes(result[0].coverage_status))
})

test("listRepos returns repos with findings_count_by_severity", async () => {
  const { mock } = makeFetchMock({ repos: [SUMMARY] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  const result = await listRepos()

  const sev = result[0].findings_count_by_severity
  assert.equal(typeof sev.critical, "number")
  assert.equal(typeof sev.high, "number")
  assert.equal(typeof sev.medium, "number")
  assert.equal(typeof sev.low, "number")
})

// ---------------------------------------------------------------------------
// Detail page: getRepo returns null on 404, throws otherwise
// ---------------------------------------------------------------------------

test("getRepo returns null for 404", async () => {
  const { mock } = makeFetchMock({ error: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadApi()
  const result = await getRepo("acme-org/missing")
  assert.equal(result, null)
})

test("getRepo re-throws on 500", async () => {
  const { mock } = makeFetchMock({ detail: "Internal Server Error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadApi()
  await assert.rejects(() => getRepo("acme-org/broken"), (err: any) => {
    assert.equal(err.status, 500)
    return true
  })
})

// ---------------------------------------------------------------------------
// Scanners_with_coverage contains only known tool keys
// ---------------------------------------------------------------------------

test("scanners_with_coverage values are known tool keys", async () => {
  const KNOWN_TOOLS = ["dependencies", "code_scanning", "container_scanning", "secrets"]
  const repo = {
    ...SUMMARY,
    scanners_with_coverage: ["dependencies", "secrets"],
  }
  const { mock } = makeFetchMock({ repos: [repo] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  const result = await listRepos()

  for (const tool of result[0].scanners_with_coverage) {
    assert.ok(KNOWN_TOOLS.includes(tool), `Unknown tool: ${tool}`)
  }
})

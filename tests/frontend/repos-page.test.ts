import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Page-level integration tests for the listRepos/getRepo helpers in
// sources-api.ts (which replaced the legacy repos-api.ts surface and now
// reads from the repoSources / source GraphQL fields).
// Validates filter forwarding, edge cases, and data shape expectations
// that the repos list and detail pages rely on.
// ---------------------------------------------------------------------------

interface FetchCall { url: string; body?: string }

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), body: init?.body as string | undefined })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadApi() {
  return import("../../frontend/lib/client/sources-api.ts")
}

// camelCase fields as returned by the Strawberry resolver.
const SOURCE = {
  type: "repo" as const,
  assetId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  displayName: "acme-org/api",
  lastScannedAt: "2026-05-30T10:00:00Z",
  findingCounts: { critical: 2, high: 1, medium: 0, low: 0 },
  repo: {
    lastScannedSha: "abc1234",
    manifestSetHash: "hash",
    scannersWithCoverage: ["dependencies_scanning"],
    coverageStatus: "fresh",
    sourceUrl: null,
  },
}

function gqlBody(over: Record<string, unknown>) {
  return { data: over }
}

// ---------------------------------------------------------------------------
// Filter forwarding: variables on the RepoSources operation
// ---------------------------------------------------------------------------

test("listRepos forwards multiple filter variables", async () => {
  const { mock, calls } = makeFetchMock(
    gqlBody({ sources: { repoSources: { sources: [], nextCursor: null, totalCount: null } } }),
  )
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  await listRepos({ org_id: "acme-org", has_critical: true, limit: 25 })

  const sent = JSON.parse(calls[0].body!)
  // org_id is accepted for back-compat but the resolver scopes via asset_ids
  // and ignores any org hint, so we don't assert it on the wire.
  assert.equal(sent.variables.hasCritical, true)
  assert.equal(sent.variables.limit, 25)
})

test("listRepos omits null filter variables when unused", async () => {
  const { mock, calls } = makeFetchMock(
    gqlBody({ sources: { repoSources: { sources: [], nextCursor: null, totalCount: null } } }),
  )
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  await listRepos({})

  const sent = JSON.parse(calls[0].body!)
  assert.equal(sent.variables.sinceDays, null)
  assert.equal(sent.variables.hasCritical, null)
  assert.equal(sent.variables.limit, 100)
})

// ---------------------------------------------------------------------------
// Coverage status values
// ---------------------------------------------------------------------------

test("listRepos returns repos with coverage_status field", async () => {
  const { mock } = makeFetchMock(
    gqlBody({ sources: { repoSources: { sources: [SOURCE], nextCursor: null, totalCount: null } } }),
  )
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  const result = await listRepos()

  assert.ok(["fresh", "stale", "never"].includes(result[0].coverage_status))
})

test("listRepos returns repos with findings_count_by_severity", async () => {
  const { mock } = makeFetchMock(
    gqlBody({ sources: { repoSources: { sources: [SOURCE], nextCursor: null, totalCount: null } } }),
  )
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
// Detail page: getRepo returns null when the source field resolves to null,
// re-throws on transport / GraphQL errors.
// ---------------------------------------------------------------------------

test("getRepo returns null when source is null", async () => {
  const { mock } = makeFetchMock(gqlBody({ sources: { source: null } }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadApi()
  const result = await getRepo("acme-org/missing")
  assert.equal(result, null)
})

test("getRepo re-throws on GraphQL error response", async () => {
  const { mock } = makeFetchMock({ errors: [{ message: "Internal server error" }] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadApi()
  await assert.rejects(
    () => getRepo("acme-org/broken"),
    (err: { message?: string }) => /Internal server error/.test(err.message ?? ""),
  )
})

// ---------------------------------------------------------------------------
// Scanners_with_coverage contains only known tool keys
// ---------------------------------------------------------------------------

test("scanners_with_coverage values are known tool keys", async () => {
  const KNOWN_TOOLS = ["dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning"]
  const source = {
    ...SOURCE,
    repo: { ...SOURCE.repo, scannersWithCoverage: ["dependencies_scanning", "secret_scanning"] },
  }
  const { mock } = makeFetchMock(
    gqlBody({ sources: { repoSources: { sources: [source], nextCursor: null, totalCount: null } } }),
  )
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadApi()
  const result = await listRepos()

  for (const tool of result[0].scanners_with_coverage) {
    assert.ok(KNOWN_TOOLS.includes(tool), `Unknown tool: ${tool}`)
  }
})

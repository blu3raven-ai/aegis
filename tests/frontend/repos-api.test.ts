import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock
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
  return import("../../lib/client/repos-api.ts")
}

const SAMPLE_SUMMARY = {
  repo_id: "acme-org/payments-api",
  org: "acme-org",
  repo: "payments-api",
  last_scanned_sha: "abc1234",
  manifest_set_hash: "hash1234",
  last_scanned_at: "2026-05-30T10:00:00Z",
  findings_count_by_severity: { critical: 1, high: 2, medium: 0, low: 3 },
  chains_count: 1,
  scanners_with_coverage: ["dependencies", "secrets"],
  coverage_status: "fresh",
  source_url: null,
}

// ---------------------------------------------------------------------------
// listRepos
// ---------------------------------------------------------------------------

test("listRepos fetches /api/v1/repos with no filters", async () => {
  const body = { repos: [SAMPLE_SUMMARY] }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  const result = await listRepos()

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/repos")
  assert.equal(result.length, 1)
  assert.equal(result[0].repo_id, "acme-org/payments-api")
})

test("listRepos encodes org_id filter", async () => {
  const { mock, calls } = makeFetchMock({ repos: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  await listRepos({ org_id: "acme-org" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("org_id"), "acme-org")
})

test("listRepos encodes since_days filter", async () => {
  const { mock, calls } = makeFetchMock({ repos: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  await listRepos({ since_days: 7 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("since_days"), "7")
})

test("listRepos encodes has_critical filter", async () => {
  const { mock, calls } = makeFetchMock({ repos: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  await listRepos({ has_critical: true })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("has_critical"), "true")
})

test("listRepos encodes limit filter", async () => {
  const { mock, calls } = makeFetchMock({ repos: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  await listRepos({ limit: 50 })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), "50")
})

test("listRepos returns empty array when repos is missing", async () => {
  const { mock } = makeFetchMock({})
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  const result = await listRepos()
  assert.deepEqual(result, [])
})

test("listRepos throws on non-ok response", async () => {
  const { mock } = makeFetchMock({ detail: "Forbidden" }, 403)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  await assert.rejects(() => listRepos(), /repos-api: 403/)
})

// ---------------------------------------------------------------------------
// getRepo
// ---------------------------------------------------------------------------

const SAMPLE_DETAIL = {
  ...SAMPLE_SUMMARY,
  scan_history: [],
  active_findings: [],
  attached_chains: [],
  default_branch: "main",
}

test("getRepo fetches by encoded repo_id", async () => {
  const { mock, calls } = makeFetchMock(SAMPLE_DETAIL)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadModule()
  const result = await getRepo("acme-org/payments-api")

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/repos/acme-org%2Fpayments-api")
  assert.ok(result !== null)
  assert.equal(result!.repo_id, "acme-org/payments-api")
})

test("getRepo returns null on 404", async () => {
  const { mock } = makeFetchMock({ error: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadModule()
  const result = await getRepo("acme-org/missing")
  assert.equal(result, null)
})

test("getRepo detail has expected shape", async () => {
  const { mock } = makeFetchMock(SAMPLE_DETAIL)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadModule()
  const result = await getRepo("acme-org/payments-api")

  assert.ok(result !== null)
  assert.ok(Array.isArray(result!.scan_history))
  assert.ok(Array.isArray(result!.active_findings))
  assert.ok(Array.isArray(result!.attached_chains))
  assert.equal(typeof result!.findings_count_by_severity.critical, "number")
})

import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string; body?: string; init?: RequestInit }

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), body: init?.body as string | undefined, init })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../frontend/lib/client/sources-api.ts")
}

// Backend GraphQL payloads use camelCase (Strawberry default).

const SAMPLE_REPO_BACKEND = {
  type: "repo" as const,
  assetId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  displayName: "acme-org/payments-api",
  lastScannedAt: "2026-05-30T10:00:00Z",
  findingCounts: { critical: 1, high: 2, medium: 0, low: 3 },
  repo: {
    lastScannedSha: "abc1234",
    manifestSetHash: "hash1234",
    scannersWithCoverage: ["dependencies_scanning", "secret_scanning"],
    coverageStatus: "fresh",
    sourceUrl: null,
  },
}

const SAMPLE_IMAGE_BACKEND = {
  type: "image" as const,
  assetId: "iiiiiiii-jjjj-kkkk-llll-mmmmmmmmmmmm",
  displayName: "acme-org/web:latest",
  lastScannedAt: "2026-06-02T10:00:00Z",
  findingCounts: { critical: 0, high: 4, medium: 1, low: 0 },
  image: {
    imageDigest: "sha256:deadbeef",
    imageName: "acme-org/web",
    imageTag: "latest",
    layerCount: 7,
    sizeBytes: 12345678,
    baseOs: "alpine:3.18",
    repos: ["acme-org/web-app"],
  },
}

function gqlBody(over: Record<string, unknown>) {
  return { data: over }
}

// ---------------------------------------------------------------------------
// listRepos (legacy-compatible flat shape; backed by repoSources GraphQL field)
// ---------------------------------------------------------------------------

test("listRepos hits /api/v1/graphql with the RepoSources operation", async () => {
  const body = gqlBody({
    sources: { repoSources: { sources: [SAMPLE_REPO_BACKEND], nextCursor: null, totalCount: null } },
  })
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  const result = await listRepos()

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/graphql")
  const sent = JSON.parse(calls[0].body!)
  assert.equal(sent.operationName, "RepoSources")
  assert.equal(result.length, 1)
  // Flattened legacy shape: asset_id reused as repo_id, display_name split into org/repo
  assert.equal(result[0].repo_id, SAMPLE_REPO_BACKEND.assetId)
  assert.equal(result[0].asset_id, SAMPLE_REPO_BACKEND.assetId)
  assert.equal(result[0].org, "acme-org")
  assert.equal(result[0].repo, "payments-api")
  assert.equal(result[0].findings_count_by_severity.critical, 1)
  assert.equal(result[0].coverage_status, "fresh")
  assert.deepEqual(result[0].scanners_with_coverage, ["dependencies_scanning", "secret_scanning"])
})

test("listRepos forwards since_days, has_critical, limit", async () => {
  const { mock, calls } = makeFetchMock(
    gqlBody({ sources: { repoSources: { sources: [], nextCursor: null, totalCount: null } } }),
  )
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  await listRepos({ since_days: 7, has_critical: true, limit: 50 })

  const sent = JSON.parse(calls[0].body!)
  assert.equal(sent.variables.sinceDays, 7)
  assert.equal(sent.variables.hasCritical, true)
  assert.equal(sent.variables.limit, 50)
})

test("listRepos returns empty array when sources is missing", async () => {
  const { mock } = makeFetchMock(gqlBody({ sources: { repoSources: { sources: [] } } }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  const result = await listRepos()
  assert.deepEqual(result, [])
})

test("listRepos throws when the GraphQL response carries errors", async () => {
  const { mock } = makeFetchMock({ errors: [{ message: "Permission denied" }] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listRepos } = await loadModule()
  await assert.rejects(
    () => listRepos(),
    (err: { message?: string }) => /Permission denied/.test(err.message ?? ""),
  )
})

// ---------------------------------------------------------------------------
// listImages (legacy-compatible flat shape; backed by imageSources GraphQL field)
// ---------------------------------------------------------------------------

test("listImages posts the ImageSources operation and flattens response", async () => {
  const body = gqlBody({
    sources: { imageSources: { sources: [SAMPLE_IMAGE_BACKEND], nextCursor: "cursor-abc", totalCount: 1 } },
  })
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listImages } = await loadModule()
  const result = await listImages()

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/graphql")
  const sent = JSON.parse(calls[0].body!)
  assert.equal(sent.operationName, "ImageSources")
  assert.equal(result.images.length, 1)
  assert.equal(result.images[0].image_digest, "sha256:deadbeef")
  assert.equal(result.images[0].base_os, "alpine:3.18")
  assert.equal(result.next_cursor, "cursor-abc")
  assert.equal(result.total_count, 1)
})

test("listImages forwards cursor and limit", async () => {
  const { mock, calls } = makeFetchMock(
    gqlBody({ sources: { imageSources: { sources: [], nextCursor: null, totalCount: 0 } } }),
  )
  globalThis.fetch = mock as unknown as typeof fetch

  const { listImages } = await loadModule()
  await listImages({ cursor: "abc==", limit: 10 })

  const sent = JSON.parse(calls[0].body!)
  assert.equal(sent.variables.cursor, "abc==")
  assert.equal(sent.variables.limit, 10)
})

// ---------------------------------------------------------------------------
// getRepo (legacy-flat; backed by source GraphQL field with polymorphic union)
// ---------------------------------------------------------------------------

const SAMPLE_REPO_DETAIL_BACKEND = {
  ...SAMPLE_REPO_BACKEND,
  __typename: "SourceRepoDetail" as const,
  scanHistory: [],
  activeFindings: [],
  defaultBranch: "main",
}

test("getRepo fetches via the source GraphQL field and flattens", async () => {
  const { mock, calls } = makeFetchMock(gqlBody({ sources: { source: SAMPLE_REPO_DETAIL_BACKEND } }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadModule()
  const result = await getRepo(SAMPLE_REPO_BACKEND.assetId)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/graphql")
  const sent = JSON.parse(calls[0].body!)
  assert.equal(sent.operationName, "SourceDetail")
  assert.equal(sent.variables.assetId, SAMPLE_REPO_BACKEND.assetId)
  assert.ok(result !== null)
  assert.equal(result!.repo_id, SAMPLE_REPO_BACKEND.assetId)
  assert.equal(result!.org, "acme-org")
  assert.equal(result!.default_branch, "main")
})

test("getRepo returns null when source resolves to null", async () => {
  const { mock } = makeFetchMock(gqlBody({ sources: { source: null } }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadModule()
  const result = await getRepo("missing-id")
  assert.equal(result, null)
})

test("getRepo returns null when asset is an image, not a repo", async () => {
  const { mock } = makeFetchMock(gqlBody({
    sources: {
      source: {
        ...SAMPLE_IMAGE_BACKEND,
        __typename: "SourceImageDetail",
        scanHistory: [],
        activeFindings: [],
      },
    },
  }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { getRepo } = await loadModule()
  const result = await getRepo(SAMPLE_IMAGE_BACKEND.assetId)
  assert.equal(result, null)
})

// ---------------------------------------------------------------------------
// submitScan (polymorphic body) — unchanged from the REST contract
// ---------------------------------------------------------------------------

// The api-client requires a __Host-csrf cookie for POST/PUT/PATCH/DELETE.
// Plant one on the global document stub so the submitScan tests can run.
function withCsrfCookie() {
  ;(globalThis as { document?: { cookie: string } }).document = {
    cookie: "__Host-csrf=test-csrf-token",
  }
}

test("submitScan posts to /api/v1/scans/manual with asset_id + commit_sha", async () => {
  withCsrfCookie()
  const { mock, calls } = makeFetchMock({
    scan_id: "scan-1", repo_id: "acme/api", commit_sha: "abc1234",
    scanner_types: [], status: "queued",
    submitted_at: "2026-06-16T00:00:00Z", submitted_by: "u1",
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { submitScan } = await loadModule()
  await submitScan(SAMPLE_REPO_BACKEND.assetId, { commitSha: "abc1234" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/scans/manual")
  const body = JSON.parse(calls[0].body!)
  assert.equal(body.asset_id, SAMPLE_REPO_BACKEND.assetId)
  assert.equal(body.commit_sha, "abc1234")
  assert.equal(body.image_digest, undefined)
})

test("submitScan accepts imageDigest for image assets", async () => {
  withCsrfCookie()
  const { mock, calls } = makeFetchMock({
    scan_id: "scan-2", repo_id: "", commit_sha: "",
    scanner_types: [], status: "queued",
    submitted_at: "2026-06-16T00:00:00Z", submitted_by: "u1",
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { submitScan } = await loadModule()
  await submitScan(SAMPLE_IMAGE_BACKEND.assetId, { imageDigest: "sha256:abc" })

  const body = JSON.parse(calls[0].body!)
  assert.equal(body.asset_id, SAMPLE_IMAGE_BACKEND.assetId)
  assert.equal(body.image_digest, "sha256:abc")
  assert.equal(body.commit_sha, undefined)
})

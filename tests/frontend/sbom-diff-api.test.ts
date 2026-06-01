import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string; method?: string }

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), method: init?.method ?? "GET" })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../lib/client/sbom-diff-api.ts")
}

// ---------------------------------------------------------------------------
// diffSbomsByRepo
// ---------------------------------------------------------------------------

const SAMPLE_DIFF = {
  added: [{ name: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21", type: "library" }],
  removed: [{ name: "underscore", version: "1.13.6", purl: "pkg:npm/underscore@1.13.6", type: "library" }],
  version_changed: [
    { name: "react", purl: "pkg:npm/react@18.2.0", from_version: "18.2.0", to_version: "18.3.1" },
  ],
  unchanged_count: 42,
}

test("diffSbomsByRepo builds correct GET URL with query params", async () => {
  const { mock, calls } = makeFetchMock(SAMPLE_DIFF)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await diffSbomsByRepo({ repo_id: "payments-api", from_hash: "abc123", to_hash: "def456" })

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/sboms/diff")
  assert.equal(url.searchParams.get("repo_id"), "payments-api")
  assert.equal(url.searchParams.get("from_hash"), "abc123")
  assert.equal(url.searchParams.get("to_hash"), "def456")
})

test("diffSbomsByRepo returns parsed diff response", async () => {
  const { mock } = makeFetchMock(SAMPLE_DIFF)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  const result = await diffSbomsByRepo({ repo_id: "payments-api", from_hash: "abc", to_hash: "def" })

  assert.equal(result.added.length, 1)
  assert.equal(result.added[0].name, "lodash")
  assert.equal(result.removed.length, 1)
  assert.equal(result.removed[0].name, "underscore")
  assert.equal(result.version_changed.length, 1)
  assert.equal(result.version_changed[0].name, "react")
  assert.equal(result.version_changed[0].from_version, "18.2.0")
  assert.equal(result.version_changed[0].to_version, "18.3.1")
  assert.equal(result.unchanged_count, 42)
})

test("diffSbomsByRepo handles empty diff gracefully", async () => {
  const emptyDiff = { added: [], removed: [], version_changed: [], unchanged_count: 100 }
  const { mock } = makeFetchMock(emptyDiff)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  const result = await diffSbomsByRepo({ repo_id: "auth-service", from_hash: "a", to_hash: "b" })

  assert.equal(result.added.length, 0)
  assert.equal(result.removed.length, 0)
  assert.equal(result.version_changed.length, 0)
  assert.equal(result.unchanged_count, 100)
})

test("diffSbomsByRepo throws on non-OK response", async () => {
  const { mock } = makeFetchMock({ detail: "SBOM not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await assert.rejects(
    () => diffSbomsByRepo({ repo_id: "missing", from_hash: "a", to_hash: "b" }),
    /sbom-diff-api: 404/,
  )
})

test("diffSbomsByRepo throws on 500 server error", async () => {
  const { mock } = makeFetchMock({ detail: "Internal Server Error" }, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await assert.rejects(
    () => diffSbomsByRepo({ repo_id: "payments-api", from_hash: "a", to_hash: "b" }),
    /sbom-diff-api: 500/,
  )
})

test("diffSbomsByRepo encodes special chars in repo_id", async () => {
  const { mock, calls } = makeFetchMock(SAMPLE_DIFF)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await diffSbomsByRepo({ repo_id: "org/repo name", from_hash: "a", to_hash: "b" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("repo_id"), "org/repo name")
})

import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string }

function makeFetchMock(body: unknown, status = 200, isText = false) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    calls.push({ url: input.toString() })
    const text = typeof body === "string" ? body : JSON.stringify(body)
    return new Response(text, {
      status,
      headers: { "Content-Type": isText ? "text/plain" : "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../lib/client/sbom-api.ts")
}

// ---------------------------------------------------------------------------
// fetchSbomHistory
// ---------------------------------------------------------------------------

test("fetchSbomHistory builds URL with repoId", async () => {
  const history = [
    { manifest_set_hash: "abc123", created_at: "2026-05-01T00:00:00Z", blob_pointer: "s3://bucket/abc123" },
  ]
  const { mock, calls } = makeFetchMock(history)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  const result = await fetchSbomHistory("payments-api")

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/sboms/repo/payments-api/history")
  assert.equal(result.length, 1)
  assert.equal(result[0].manifest_set_hash, "abc123")
})

test("fetchSbomHistory encodes special chars in repoId", async () => {
  const { mock, calls } = makeFetchMock([])
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  await fetchSbomHistory("org/repo name")

  const url = new URL(calls[0].url, "http://localhost")
  assert.ok(url.pathname.includes("org%2Frepo%20name"), `Expected encoded path, got: ${url.pathname}`)
})

test("fetchSbomHistory forwards optional limit param", async () => {
  const { mock, calls } = makeFetchMock([])
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  await fetchSbomHistory("payments-api", 5)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), "5")
})

test("fetchSbomHistory accepts wrapped { items: [...] } shape", async () => {
  const { mock } = makeFetchMock({
    items: [
      { manifest_set_hash: "def456", created_at: "2026-05-10T00:00:00Z", blob_pointer: "s3://bucket/def456" },
    ],
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  const result = await fetchSbomHistory("payments-api")
  assert.equal(result.length, 1)
  assert.equal(result[0].manifest_set_hash, "def456")
})

test("fetchSbomHistory throws on non-OK response", async () => {
  const { mock } = makeFetchMock({ detail: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  await assert.rejects(
    () => fetchSbomHistory("unknown-repo"),
    /sbom-api: 404/,
  )
})

// ---------------------------------------------------------------------------
// fetchSbom
// ---------------------------------------------------------------------------

test("fetchSbom builds URL for repoId with default format", async () => {
  const { mock, calls } = makeFetchMock("{}", 200, true)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbom } = await loadModule()
  await fetchSbom({ repoId: "payments-api" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/sboms/repo/payments-api")
  assert.equal(url.searchParams.get("format"), "cyclonedx-json")
})

test("fetchSbom builds URL for imageDigest", async () => {
  const { mock, calls } = makeFetchMock("{}", 200, true)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbom } = await loadModule()
  await fetchSbom({ imageDigest: "sha256:abc123", format: "spdx-json" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/sboms/image/sha256%3Aabc123")
  assert.equal(url.searchParams.get("format"), "spdx-json")
})

test("fetchSbom throws when neither repoId nor imageDigest provided", async () => {
  const { fetchSbom } = await loadModule()
  await assert.rejects(
    () => fetchSbom({}),
    /repoId or imageDigest/,
  )
})

test("fetchSbom throws on non-OK response", async () => {
  const { mock } = makeFetchMock("Server Error", 500, true)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbom } = await loadModule()
  await assert.rejects(
    () => fetchSbom({ repoId: "payments-api" }),
    /sbom-api: 500/,
  )
})

// ---------------------------------------------------------------------------
// parseCycloneDxJson
// ---------------------------------------------------------------------------

const SAMPLE_CYCLONEDX = JSON.stringify({
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  metadata: {
    timestamp: "2026-05-01T12:00:00Z",
    tools: [{ name: "aegis-scanner", version: "1.0.0" }],
  },
  components: [
    {
      type: "library",
      name: "express",
      version: "4.18.2",
      purl: "pkg:npm/express@4.18.2",
      licenses: [{ license: { id: "MIT" } }],
      hashes: [{ alg: "SHA-256", content: "abc123def456" }],
    },
    {
      type: "library",
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
    },
  ],
  dependencies: [
    { ref: "pkg:npm/express@4.18.2", dependsOn: ["pkg:npm/lodash@4.17.21"] },
    { ref: "pkg:npm/lodash@4.17.21", dependsOn: [] },
  ],
})

test("parseCycloneDxJson extracts metadata timestamp", async () => {
  const { parseCycloneDxJson } = await loadModule()
  const result = parseCycloneDxJson(SAMPLE_CYCLONEDX)

  assert.equal(result.metadata?.timestamp, "2026-05-01T12:00:00Z")
  assert.equal(Array.isArray(result.metadata?.tools), true)
})

test("parseCycloneDxJson extracts components correctly", async () => {
  const { parseCycloneDxJson } = await loadModule()
  const result = parseCycloneDxJson(SAMPLE_CYCLONEDX)

  assert.equal(result.components.length, 2)
  const express = result.components[0]
  assert.equal(express.name, "express")
  assert.equal(express.version, "4.18.2")
  assert.equal(express.type, "library")
  assert.equal(express.purl, "pkg:npm/express@4.18.2")
  assert.equal(express.licenses?.[0]?.license.id, "MIT")
  assert.equal(express.hashes?.[0]?.alg, "SHA-256")
  assert.equal(express.hashes?.[0]?.content, "abc123def456")
})

test("parseCycloneDxJson extracts dependencies", async () => {
  const { parseCycloneDxJson } = await loadModule()
  const result = parseCycloneDxJson(SAMPLE_CYCLONEDX)

  assert.equal(result.dependencies.length, 2)
  assert.equal(result.dependencies[0].ref, "pkg:npm/express@4.18.2")
  assert.deepEqual(result.dependencies[0].dependsOn, ["pkg:npm/lodash@4.17.21"])
})

test("parseCycloneDxJson handles empty components array", async () => {
  const { parseCycloneDxJson } = await loadModule()
  const result = parseCycloneDxJson(JSON.stringify({ components: [], dependencies: [] }))

  assert.equal(result.components.length, 0)
  assert.equal(result.dependencies.length, 0)
  assert.equal(result.metadata, undefined)
})

test("parseCycloneDxJson handles missing optional fields gracefully", async () => {
  const { parseCycloneDxJson } = await loadModule()
  const result = parseCycloneDxJson(
    JSON.stringify({
      components: [{ name: "minimal-pkg", version: "1.0.0" }],
      dependencies: [],
    }),
  )

  assert.equal(result.components[0].type, "library")
  assert.equal(result.components[0].purl, undefined)
  assert.equal(result.components[0].licenses, undefined)
})

test("parseCycloneDxJson throws on invalid JSON", async () => {
  const { parseCycloneDxJson } = await loadModule()
  assert.throws(() => parseCycloneDxJson("not valid json {{{"), /invalid JSON/)
})

test("parseCycloneDxJson returns empty sbom for non-object JSON (array)", async () => {
  const { parseCycloneDxJson } = await loadModule()
  // An array is valid JSON but has no CycloneDX fields — parser returns empty safely
  const result = parseCycloneDxJson("[1, 2, 3]")
  assert.equal(result.components.length, 0)
  assert.equal(result.dependencies.length, 0)
})

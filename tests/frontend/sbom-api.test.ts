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
  return import("../../frontend/lib/client/sbom-api.ts")
}

// ---------------------------------------------------------------------------
// fetchSbomHistory — GraphQL (Query.sbom.history)
// ---------------------------------------------------------------------------

function gqlHistoryResponse(history: Array<{ runId: string; createdAt: string | null; key: string }>) {
  return { data: { sbom: { history } } }
}

function makeGqlFetchMock(payload: unknown, status = 200) {
  const calls: Array<{ url: string; body: { operationName: string; variables: Record<string, unknown> } }> = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({
      url: input.toString(),
      body: JSON.parse(init?.body as string) as { operationName: string; variables: Record<string, unknown> },
    })
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

test("fetchSbomHistory POSTs to /api/v1/graphql with operationName SbomHistory", async () => {
  const { mock, calls } = makeGqlFetchMock(gqlHistoryResponse([]))
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  await fetchSbomHistory("payments-api")

  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(calls[0].body.operationName, "SbomHistory")
})

test("fetchSbomHistory passes repo + default limit variables", async () => {
  const { mock, calls } = makeGqlFetchMock(gqlHistoryResponse([]))
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  await fetchSbomHistory("payments-api")

  assert.equal(calls[0].body.variables.repo, "payments-api")
  assert.equal(calls[0].body.variables.limit, 10)
})

test("fetchSbomHistory forwards explicit limit variable", async () => {
  const { mock, calls } = makeGqlFetchMock(gqlHistoryResponse([]))
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  await fetchSbomHistory("payments-api", 5)

  assert.equal(calls[0].body.variables.limit, 5)
})

test("fetchSbomHistory maps camelCase response to snake_case entries", async () => {
  const payload = gqlHistoryResponse([
    { runId: "run-abc", createdAt: "2026-05-01T00:00:00Z", key: "sboms/run-abc.cdx.json" },
  ])
  const { mock } = makeGqlFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  const result = await fetchSbomHistory("payments-api")

  assert.equal(result.length, 1)
  assert.equal(result[0].run_id, "run-abc")
  assert.equal(result[0].created_at, "2026-05-01T00:00:00Z")
  assert.equal(result[0].key, "sboms/run-abc.cdx.json")
})

test("fetchSbomHistory throws when GraphQL response has errors", async () => {
  const { mock } = makeGqlFetchMock({ errors: [{ message: "denied" }] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadModule()
  await assert.rejects(() => fetchSbomHistory("payments-api"), /denied/)
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
    (err: any) => {
      assert.equal(err.status, 500)
      return true
    },
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
  // licenses are normalized to display strings (SPDX id / name / expression),
  // not the raw CycloneDX `{ license: { id } }` shape.
  assert.equal(express.licenses?.[0], "MIT")
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

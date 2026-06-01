import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests that validate page-level integration: API calls triggered from the
// SBOM browser pages, export flow, and history drawer state logic.
//
// These are pure logic / API-layer tests — no DOM rendering required.
// ---------------------------------------------------------------------------

interface FetchCall { url: string; method: string }

function makeFetchMock(
  handler: (url: string) => { body: unknown; status?: number; isText?: boolean },
) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString()
    calls.push({ url, method: (init?.method ?? "GET").toUpperCase() })
    const { body, status = 200, isText = false } = handler(url)
    const text = typeof body === "string" ? body : JSON.stringify(body)
    return new Response(text, {
      status,
      headers: { "Content-Type": isText ? "text/plain" : "application/json" },
    })
  }
  return { mock, calls }
}

async function loadSbomApi() {
  return import("../../lib/client/sbom-api.ts")
}

// ---------------------------------------------------------------------------
// Export flow — fetchSbom + download (no DOM, just verify the fetch call)
// ---------------------------------------------------------------------------

test("export flow: fetchSbom called with correct format for cyclonedx-xml", async () => {
  const { mock, calls } = makeFetchMock(() => ({ body: "<xml/>", isText: true }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbom } = await loadSbomApi()
  await fetchSbom({ repoId: "payments-api", format: "cyclonedx-xml" })

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("format"), "cyclonedx-xml")
})

test("export flow: fetchSbom called with spdx-json format", async () => {
  const { mock, calls } = makeFetchMock(() => ({ body: "{}", isText: true }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbom } = await loadSbomApi()
  await fetchSbom({ repoId: "auth-service", format: "spdx-json" })

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("format"), "spdx-json")
  assert.ok(url.pathname.includes("auth-service"))
})

// ---------------------------------------------------------------------------
// History drawer state logic
// ---------------------------------------------------------------------------

test("history drawer: loads entries, selects latest hash by default", async () => {
  const history = [
    { manifest_set_hash: "latest111", created_at: "2026-05-30T10:00:00Z", blob_pointer: "s3://a" },
    { manifest_set_hash: "older222", created_at: "2026-05-29T10:00:00Z", blob_pointer: "s3://b" },
    { manifest_set_hash: "oldest333", created_at: "2026-05-28T10:00:00Z", blob_pointer: "s3://c" },
  ]
  const { mock, calls } = makeFetchMock(() => ({ body: history }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbomHistory } = await loadSbomApi()
  const result = await fetchSbomHistory("payments-api")

  assert.equal(calls.length, 1)
  assert.equal(result.length, 3)
  // First entry is the latest — UI picks this as selected hash
  assert.equal(result[0].manifest_set_hash, "latest111")
})

test("history drawer: clicking a version re-fetches SBOM", async () => {
  let callCount = 0
  const { mock, calls } = makeFetchMock((url) => {
    callCount++
    if (url.includes("/history")) return { body: [] }
    return { body: JSON.stringify({ components: [], dependencies: [] }), isText: true }
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbom, fetchSbomHistory } = await loadSbomApi()

  // Initial page load
  await fetchSbomHistory("payments-api")
  await fetchSbom({ repoId: "payments-api", format: "cyclonedx-json" })

  // User selects a different version — page re-fetches SBOM
  await fetchSbom({ repoId: "payments-api", format: "cyclonedx-json" })

  // Should have made 3 calls: 1 history + 2 SBOM fetches
  assert.equal(calls.length, 3)
})

// ---------------------------------------------------------------------------
// Export dropdown — format-to-filename mapping
// ---------------------------------------------------------------------------

test("export filename: cyclonedx-json produces .cyclonedx.json suffix", () => {
  // Mimic the SbomExportMenu handleSelect logic
  const repoName = "payments-api"
  const safeName = repoName.replace(/[^a-z0-9_.-]/gi, "-").toLowerCase()
  const ext = "cyclonedx.json"
  const filename = `${safeName}.${ext}`
  assert.equal(filename, "payments-api.cyclonedx.json")
})

test("export filename: special chars in repo name are sanitised", () => {
  const repoName = "example-org/my repo (v2)"
  const safeName = repoName.replace(/[^a-z0-9_.-]/gi, "-").toLowerCase()
  const ext = "spdx.json"
  const filename = `${safeName}.${ext}`
  assert.ok(!filename.includes("/"), "Filename should not contain slashes")
  assert.ok(!filename.includes(" "), "Filename should not contain spaces")
  assert.ok(filename.endsWith(".spdx.json"))
})

// ---------------------------------------------------------------------------
// parseCycloneDxJson — page-level scenarios
// ---------------------------------------------------------------------------

test("page: renders component count from parseCycloneDxJson", async () => {
  const { parseCycloneDxJson } = await loadSbomApi()
  const sbomText = JSON.stringify({
    components: [
      { name: "express", version: "4.18.2", type: "library" },
      { name: "lodash", version: "4.17.21", type: "library" },
      { name: "react", version: "18.2.0", type: "library" },
    ],
    dependencies: [
      { ref: "pkg:npm/express@4.18.2", dependsOn: ["pkg:npm/lodash@4.17.21"] },
    ],
  })

  const parsed = parseCycloneDxJson(sbomText)
  assert.equal(parsed.components.length, 3)
  assert.equal(parsed.dependencies.length, 1)
})

test("page: empty SBOM shows empty state (no components)", async () => {
  const { parseCycloneDxJson } = await loadSbomApi()
  const parsed = parseCycloneDxJson(JSON.stringify({ components: [], dependencies: [] }))
  assert.equal(parsed.components.length, 0)
  // Page should show empty state when components.length === 0
})

test("page: error on 404 for unknown repo", async () => {
  const { mock } = makeFetchMock(() => ({ body: { detail: "Not Found" }, status: 404 }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { fetchSbom } = await loadSbomApi()
  await assert.rejects(
    () => fetchSbom({ repoId: "nonexistent-repo" }),
    /sbom-api: 404/,
  )
})

import test from "node:test"
import assert from "node:assert/strict"
import { ApiClientError } from "../../frontend/lib/client/api-client.types.ts"

interface FetchCall {
  url: string
  init?: RequestInit
}

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), init })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../frontend/lib/client/search-api.ts")
}

test("search builds correct URL for a basic query", async () => {
  const body = { query: "cve", total: 0, grouped: {}, duration_ms: 1 }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("cve")
  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/search")
  assert.equal(url.searchParams.get("q"), "cve")
})

test("search includes scope when provided", async () => {
  const body = { query: "x", total: 0, grouped: {}, duration_ms: 0 }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x", { scopes: ["findings", "chains"] })
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("scope"), "findings,chains")
})

test("search omits scope param when not provided", async () => {
  const body = { query: "x", total: 0, grouped: {}, duration_ms: 0 }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x")
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("scope"), null)
})

test("search includes non-default limit in URL", async () => {
  const body = { query: "x", total: 0, grouped: {}, duration_ms: 0 }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x", { limit: 10 })
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), "10")
})

test("search omits limit param when using default (50)", async () => {
  const body = { query: "x", total: 0, grouped: {}, duration_ms: 0 }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x", { limit: 50 })
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("limit"), null)
})

test("search returns parsed SearchResults", async () => {
  const body = {
    query: "CVE-2023",
    total: 1,
    grouped: {
      findings: [{
        type: "finding", id: "42", title: "CVE-2023-0001",
        subtitle: "payments-api", href: "/dependencies/dashboard",
        score: 0.7, metadata: { severity: "high" },
      }],
    },
    duration_ms: 3,
  }
  const { mock } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  const result = await search("CVE-2023")
  assert.equal(result.query, "CVE-2023")
  assert.equal(result.total, 1)
  assert.ok("findings" in result.grouped)
  assert.equal(result.grouped["findings"][0].title, "CVE-2023-0001")
})

test("search throws on non-OK response", async () => {
  const { mock } = makeFetchMock({ detail: "Unauthorized" }, 401)
  globalThis.fetch = mock as unknown as typeof fetch
  // Suppress window.location.assign that apiClient triggers on 401
  globalThis.window = { location: { assign: () => {} } } as unknown as Window & typeof globalThis
  const { search } = await loadModule()
  await assert.rejects(
    () => search("test"),
    (e: unknown) => e instanceof ApiClientError && e.status === 401,
  )
})

test("search passes signal to fetch", async () => {
  const body = { query: "x", total: 0, grouped: {}, duration_ms: 0 }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  const controller = new AbortController()
  await search("x", { signal: controller.signal })
  assert.ok(calls[0].init?.signal instanceof AbortSignal)
})

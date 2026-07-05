import test from "node:test"
import assert from "node:assert/strict"

interface FetchCall {
  url: string
  init?: RequestInit
}

function makeFetchMock(payload: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), init })
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

function makeGraphQLResponse(over: Partial<{
  query: string
  total: number
  durationMs: number
  findings: unknown[]
  repos: unknown[]
  auditEvents: unknown[]
  destinations: unknown[]
}> = {}) {
  return {
    data: {
      findings: {
        globalSearch: {
          query: "",
          total: 0,
          durationMs: 0,
          findings: [],
          repos: [],
          auditEvents: [],
          destinations: [],
          ...over,
        },
      },
    },
  }
}

async function loadModule() {
  return import("../../frontend/lib/client/search-api.ts")
}

test("search posts to /api/v1/graphql with the GlobalSearch operation", async () => {
  const { mock, calls } = makeFetchMock(makeGraphQLResponse({ query: "cve" }))
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("cve")
  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/graphql")
  assert.equal(calls[0].init?.method, "POST")
  const body = JSON.parse(String(calls[0].init?.body))
  assert.equal(body.operationName, "GlobalSearch")
  assert.equal(body.variables.q, "cve")
})

test("search forwards scopes when provided", async () => {
  const { mock, calls } = makeFetchMock(makeGraphQLResponse())
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x", { scopes: ["findings", "repos"] })
  const body = JSON.parse(String(calls[0].init?.body))
  assert.deepEqual(body.variables.scopes, ["findings", "repos"])
})

test("search sends null scopes when not provided", async () => {
  const { mock, calls } = makeFetchMock(makeGraphQLResponse())
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x")
  const body = JSON.parse(String(calls[0].init?.body))
  assert.equal(body.variables.scopes, null)
})

test("search forwards limit", async () => {
  const { mock, calls } = makeFetchMock(makeGraphQLResponse())
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x", { limit: 10 })
  const body = JSON.parse(String(calls[0].init?.body))
  assert.equal(body.variables.limit, 10)
})

test("search defaults limit to 50", async () => {
  const { mock, calls } = makeFetchMock(makeGraphQLResponse())
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await search("x")
  const body = JSON.parse(String(calls[0].init?.body))
  assert.equal(body.variables.limit, 50)
})

test("search returns SearchResults shape with snake_case keys", async () => {
  const findings = [{
    type: "finding", id: "42", title: "CVE-2023-0001",
    subtitle: "payments-api", href: "/findings?scanner=dependencies_scanning",
    score: 0.7, metadata: { severity: "high" },
  }]
  const auditEvents = [{
    type: "audit_event", id: "1", title: "user_login",
    subtitle: "now", href: "/settings/audit",
    score: 0.4, metadata: {},
  }]
  const { mock } = makeFetchMock(makeGraphQLResponse({
    query: "CVE-2023",
    total: 2,
    durationMs: 3,
    findings,
    auditEvents,
  }))
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  const result = await search("CVE-2023")
  assert.equal(result.query, "CVE-2023")
  assert.equal(result.total, 2)
  assert.equal(result.duration_ms, 3)
  assert.equal(result.grouped.findings[0].title, "CVE-2023-0001")
  assert.equal(result.grouped.audit_events[0].title, "user_login")
})

test("search throws on non-OK response", async () => {
  const { mock } = makeFetchMock({ detail: "Unauthorized" }, 401)
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await assert.rejects(
    () => search("test"),
    (e: unknown) => e instanceof Error && /401/.test((e as Error).message),
  )
})

test("search throws when GraphQL response contains errors", async () => {
  const { mock } = makeFetchMock({
    errors: [{ message: "Operation must be named for observability" }],
  })
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  await assert.rejects(
    () => search("x"),
    (e: unknown) => e instanceof Error && /named for observability/.test((e as Error).message),
  )
})

test("search passes signal to fetch", async () => {
  const { mock, calls } = makeFetchMock(makeGraphQLResponse())
  globalThis.fetch = mock as unknown as typeof fetch
  const { search } = await loadModule()
  const controller = new AbortController()
  await search("x", { signal: controller.signal })
  assert.ok(calls[0].init?.signal instanceof AbortSignal)
})

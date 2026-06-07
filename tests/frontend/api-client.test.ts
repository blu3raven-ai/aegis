import { test, describe, beforeEach } from "node:test"
import assert from "node:assert/strict"

import { apiClient, type ApiClientOptions } from "../../frontend/lib/client/api-client.ts"
import { ApiClientError, CsrfMissingError } from "../../frontend/lib/client/api-client.types.ts"

function withDocumentCookie(value: string) {
  globalThis.document = { cookie: value } as Document
}

function withFetchMock(fn: typeof fetch) {
  globalThis.fetch = fn as typeof fetch
}

describe("apiClient", () => {
  beforeEach(() => {
    delete (globalThis as { document?: Document }).document
  })

  test("GET sends credentials but no CSRF header", async () => {
    withDocumentCookie("__Host-csrf=abc123")
    let received: RequestInit | undefined
    withFetchMock(async (_url, init) => {
      received = init
      return new Response('{"ok":true}', { status: 200 })
    })

    await apiClient("/api/v1/findings", { method: "GET" })

    assert.equal(received?.credentials, "include")
    assert.equal((received?.headers as Record<string, string>)["X-CSRF-Token"], undefined)
  })

  test("POST attaches CSRF header from cookie", async () => {
    withDocumentCookie("__Host-csrf=xyz789; other=val")
    let receivedHeaders: Record<string, string> = {}
    withFetchMock(async (_url, init) => {
      receivedHeaders = init?.headers as Record<string, string>
      return new Response('{"ok":true}', { status: 200 })
    })

    await apiClient("/api/v1/findings/x/decision", { method: "POST", body: { reason: "x" } })

    assert.equal(receivedHeaders["X-CSRF-Token"], "xyz789")
    assert.equal(receivedHeaders["Content-Type"], "application/json")
  })

  test("POST without CSRF cookie throws CsrfMissingError", async () => {
    withDocumentCookie("other=val")
    withFetchMock(async () => new Response("", { status: 200 }))

    await assert.rejects(
      apiClient("/api/v1/findings", { method: "POST", body: {} }),
      (e: Error) => e instanceof CsrfMissingError,
    )
  })

  test("401 response triggers redirect to /login", async () => {
    withDocumentCookie("__Host-csrf=abc")
    let redirected = ""
    globalThis.window = {
      location: { assign: (url: string) => { redirected = url } } as Location,
    } as Window & typeof globalThis
    withFetchMock(async () => new Response('{"detail":"unauthorized"}', { status: 401 }))

    await assert.rejects(apiClient("/api/v1/findings", { method: "GET" }))
    assert.equal(redirected, "/login")
  })

  test("non-2xx, non-401 raises ApiClientError with status and body", async () => {
    withDocumentCookie("")
    withFetchMock(async () =>
      new Response('{"detail":"bad request"}', { status: 400, headers: { "Content-Type": "application/json" } }),
    )

    await assert.rejects(
      apiClient("/api/v1/findings", { method: "GET" }),
      (e: ApiClientError) => {
        return e.status === 400 && (e.body as { detail: string }).detail === "bad request"
      },
    )
  })

  test("2xx JSON response is parsed and returned", async () => {
    withDocumentCookie("")
    withFetchMock(async () =>
      new Response('{"findings": [{"id":"f1"}]}', { status: 200, headers: { "Content-Type": "application/json" } }),
    )

    const result = await apiClient<{ findings: { id: string }[] }>("/api/v1/findings")
    assert.deepEqual(result, { findings: [{ id: "f1" }] })
  })

  test("204 No Content returns undefined", async () => {
    withDocumentCookie("__Host-csrf=abc")
    withFetchMock(async () => new Response(null, { status: 204 }))

    const result = await apiClient("/api/v1/findings/x", { method: "DELETE" })
    assert.equal(result, undefined)
  })

  test("custom headers merge with defaults", async () => {
    withDocumentCookie("__Host-csrf=abc")
    let receivedHeaders: Record<string, string> = {}
    withFetchMock(async (_u, init) => {
      receivedHeaders = init?.headers as Record<string, string>
      return new Response('{"ok":true}', { status: 200 })
    })

    await apiClient("/api/v1/findings", {
      method: "POST",
      body: {},
      headers: { "X-Custom-Header": "custom-value" },
    })

    assert.equal(receivedHeaders["X-Custom-Header"], "custom-value")
    assert.equal(receivedHeaders["X-CSRF-Token"], "abc")
  })

  test("DELETE without CSRF cookie throws CsrfMissingError", async () => {
    withDocumentCookie("")
    withFetchMock(async () => new Response(null, { status: 204 }))

    await assert.rejects(
      apiClient("/api/v1/findings/x", { method: "DELETE" }),
      (e: Error) => e instanceof CsrfMissingError,
    )
  })

  test("401 with suppressUnauthorizedRedirect does NOT redirect", async () => {
    withDocumentCookie("__Host-csrf=abc")
    let redirected = ""
    globalThis.window = {
      location: { assign: (url: string) => { redirected = url } } as Location,
    } as Window & typeof globalThis
    withFetchMock(async () => new Response('{"detail":"invalid credentials"}', { status: 401 }))

    await assert.rejects(
      apiClient("/auth/login", { method: "POST", body: {}, suppressUnauthorizedRedirect: true }),
      (e: ApiClientError) => e.status === 401,
    )
    assert.equal(redirected, "")
  })

  test("POST with skipCsrf and no CSRF cookie sends without X-CSRF-Token", async () => {
    withDocumentCookie("")
    let receivedHeaders: Record<string, string> = {}
    let receivedInit: RequestInit | undefined
    withFetchMock(async (_u, init) => {
      receivedInit = init
      receivedHeaders = init?.headers as Record<string, string>
      return new Response('{"ok":true}', { status: 200 })
    })

    const opts: ApiClientOptions = { method: "POST", body: { identifier: "u", password: "p" }, skipCsrf: true }
    await apiClient("/auth/login", opts)

    assert.equal(receivedHeaders["X-CSRF-Token"], undefined)
    assert.equal(receivedInit?.credentials, "include")
  })

  test("POST with skipCsrf ignores any existing CSRF cookie", async () => {
    withDocumentCookie("__Host-csrf=stale-token-from-old-session")
    let receivedHeaders: Record<string, string> = {}
    withFetchMock(async (_u, init) => {
      receivedHeaders = init?.headers as Record<string, string>
      return new Response('{"ok":true}', { status: 200 })
    })

    await apiClient("/auth/login", { method: "POST", body: {}, skipCsrf: true })

    assert.equal(receivedHeaders["X-CSRF-Token"], undefined)
  })
})

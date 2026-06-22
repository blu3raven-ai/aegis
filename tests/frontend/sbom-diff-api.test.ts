import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// sbom-diff-api uses GraphQL (Query.sbom.diff) with a SbomDiffResult |
// SbomDiffError union. Tests assert the GraphQL request shape and the
// union-aware response handling.
// ---------------------------------------------------------------------------

interface FetchCall { url: string; body: { operationName: string; variables: Record<string, unknown> } }

function makeFetchMock(payload: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({
      url: input.toString(),
      body: JSON.parse(init?.body as string) as FetchCall["body"],
    })
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

function gqlDiffResult(overrides: Partial<{
  added: Array<{ name: string; version: string; purl: string; type: string }>
  removed: Array<{ name: string; version: string; purl: string; type: string }>
  versionChanged: Array<{ name: string; purl: string; fromVersion: string | null; toVersion: string | null }>
  unchangedCount: number
}> = {}) {
  return {
    data: {
      sbom: {
        diff: {
          __typename: "SbomDiffResult",
          added: overrides.added ?? [],
          removed: overrides.removed ?? [],
          versionChanged: overrides.versionChanged ?? [],
          unchangedCount: overrides.unchangedCount ?? 0,
        },
      },
    },
  }
}

function gqlDiffError(message: string, code = "NOT_FOUND") {
  return {
    data: {
      sbom: {
        diff: { __typename: "SbomDiffError", message, code },
      },
    },
  }
}

async function loadModule() {
  return import("../../frontend/lib/client/sbom-diff-api.ts")
}

// ---------------------------------------------------------------------------
// diffSbomsByRepo
// ---------------------------------------------------------------------------

test("diffSbomsByRepo POSTs to /api/v1/graphql with operationName SbomDiff", async () => {
  const { mock, calls } = makeFetchMock(gqlDiffResult())
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await diffSbomsByRepo({ repo_id: "payments-api", from_run_id: "run-a", to_run_id: "run-b" })

  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, "/api/v1/graphql")
  assert.equal(calls[0].body.operationName, "SbomDiff")
})

test("diffSbomsByRepo maps inputs to repoId/fromRunId/toRunId variables", async () => {
  const { mock, calls } = makeFetchMock(gqlDiffResult())
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await diffSbomsByRepo({ repo_id: "payments-api", from_run_id: "run-a", to_run_id: "run-b" })

  assert.equal(calls[0].body.variables.repoId, "payments-api")
  assert.equal(calls[0].body.variables.fromRunId, "run-a")
  assert.equal(calls[0].body.variables.toRunId, "run-b")
  assert.equal(calls[0].body.variables.imageDigestFrom, null)
  assert.equal(calls[0].body.variables.imageDigestTo, null)
})

test("diffSbomsByRepo unwraps SbomDiffResult and converts camelCase fields", async () => {
  const payload = gqlDiffResult({
    added: [{ name: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21", type: "library" }],
    removed: [{ name: "underscore", version: "1.13.6", purl: "pkg:npm/underscore@1.13.6", type: "library" }],
    versionChanged: [
      { name: "react", purl: "pkg:npm/react@18.2.0", fromVersion: "18.2.0", toVersion: "18.3.1" },
    ],
    unchangedCount: 42,
  })
  const { mock } = makeFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  const result = await diffSbomsByRepo({ repo_id: "payments-api", from_run_id: "a", to_run_id: "b" })

  assert.equal(result.added.length, 1)
  assert.equal(result.added[0].name, "lodash")
  assert.equal(result.removed.length, 1)
  assert.equal(result.version_changed.length, 1)
  assert.equal(result.version_changed[0].from_version, "18.2.0")
  assert.equal(result.version_changed[0].to_version, "18.3.1")
  assert.equal(result.unchanged_count, 42)
})

test("diffSbomsByRepo strips empty-string optional fields to undefined", async () => {
  const payload = gqlDiffResult({
    added: [{ name: "minimal", version: "", purl: "", type: "" }],
  })
  const { mock } = makeFetchMock(payload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  const result = await diffSbomsByRepo({ repo_id: "a", from_run_id: "b", to_run_id: "c" })

  assert.equal(result.added[0].version, undefined)
  assert.equal(result.added[0].purl, undefined)
  assert.equal(result.added[0].type, undefined)
})

test("diffSbomsByRepo throws when SbomDiffError union branch is returned", async () => {
  const { mock } = makeFetchMock(gqlDiffError("from snapshot missing"))
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await assert.rejects(
    () => diffSbomsByRepo({ repo_id: "payments-api", from_run_id: "a", to_run_id: "b" }),
    /from snapshot missing/,
  )
})

test("diffSbomsByRepo throws when GraphQL response has errors", async () => {
  const { mock } = makeFetchMock({ errors: [{ message: "denied" }] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { diffSbomsByRepo } = await loadModule()
  await assert.rejects(
    () => diffSbomsByRepo({ repo_id: "payments-api", from_run_id: "a", to_run_id: "b" }),
    /denied/,
  )
})

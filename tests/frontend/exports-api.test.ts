import test from "node:test"
import assert from "node:assert/strict"

async function loadModule() {
  return import("../../frontend/lib/client/exports-api.ts")
}

// ---------------------------------------------------------------------------
// buildFindingsExportUrl
// ---------------------------------------------------------------------------

test("builds URL with format=csv by default path structure", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({}, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.pathname, "/api/v1/exports/findings")
  assert.equal(parsed.searchParams.get("format"), "csv")
})

test("builds URL with format=json", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({}, "json")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("format"), "json")
})

test("includes severity filter", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({ severity: "critical,high" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("severity"), "critical,high")
})

test("includes scanner filter", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({ scanner: "dependencies" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("scanner"), "dependencies")
})

test("includes status filter", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({ status: "open" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("status"), "open")
})

test("includes repo_id filter", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({ repo_id: "example-org/api" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("repo_id"), "example-org/api")
})

test("includes since filter", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({ since: "2026-01-01T00:00:00Z" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("since"), "2026-01-01T00:00:00Z")
})

test("includes until filter", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({ until: "2026-06-01T00:00:00Z" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("until"), "2026-06-01T00:00:00Z")
})

test("omits undefined filters from query string", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl({ severity: "high" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.has("scanner"), false)
  assert.equal(parsed.searchParams.has("status"), false)
  assert.equal(parsed.searchParams.has("repo_id"), false)
})

test("includes all filters when all are provided", async () => {
  const { buildFindingsExportUrl } = await loadModule()
  const url = buildFindingsExportUrl(
    {
      severity: "critical",
      scanner: "secrets",
      status: "open",
      repo_id: "example-org/api",
      since: "2026-01-01T00:00:00Z",
      until: "2026-06-01T00:00:00Z",
    },
    "json",
  )
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("format"), "json")
  assert.equal(parsed.searchParams.get("severity"), "critical")
  assert.equal(parsed.searchParams.get("scanner"), "secrets")
  assert.equal(parsed.searchParams.get("status"), "open")
  assert.equal(parsed.searchParams.get("repo_id"), "example-org/api")
  assert.equal(parsed.searchParams.get("since"), "2026-01-01T00:00:00Z")
  assert.equal(parsed.searchParams.get("until"), "2026-06-01T00:00:00Z")
})

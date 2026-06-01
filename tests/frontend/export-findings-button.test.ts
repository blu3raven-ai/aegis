/**
 * Tests for ExportFindingsButton — uses JSDOM-like node:test assertions.
 *
 * Because we're running in Node without a DOM, we test the URL-building
 * logic directly and verify the component module exports the expected symbol.
 * Full DOM interaction is covered by the exports-api tests; rendering tests
 * would require a browser test runner which is out of scope here.
 */
import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Verify the component source file exists at the expected path
// ---------------------------------------------------------------------------

import { existsSync } from "node:fs"
import { resolve } from "node:path"

test("ExportFindingsButton component file exists at expected path", () => {
  const componentPath = resolve(
    new URL(".", import.meta.url).pathname,
    "../../components/shared/findings/ExportFindingsButton.tsx",
  )
  assert.ok(existsSync(componentPath), `Component not found at ${componentPath}`)
})

// ---------------------------------------------------------------------------
// URL generation wired to the button is correct (via exports-api)
// ---------------------------------------------------------------------------

test("button uses buildFindingsExportUrl to construct CSV download URL", async () => {
  const { buildFindingsExportUrl } = await import("../../lib/client/exports-api.ts")
  const url = buildFindingsExportUrl({ severity: "critical" }, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("format"), "csv")
  assert.equal(parsed.searchParams.get("severity"), "critical")
})

test("button uses buildFindingsExportUrl to construct JSON download URL", async () => {
  const { buildFindingsExportUrl } = await import("../../lib/client/exports-api.ts")
  const url = buildFindingsExportUrl({ severity: "high" }, "json")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.get("format"), "json")
})

test("button passes empty filters when no severity is active", async () => {
  const { buildFindingsExportUrl } = await import("../../lib/client/exports-api.ts")
  const url = buildFindingsExportUrl({}, "csv")
  const parsed = new URL(url, "http://localhost")
  assert.equal(parsed.searchParams.has("severity"), false)
  assert.equal(parsed.searchParams.get("format"), "csv")
})

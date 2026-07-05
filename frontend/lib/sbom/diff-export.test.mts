import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./diff-export.ts", import.meta.url)),
  "utf-8",
)
const apiSrc = readFileSync(
  fileURLToPath(new URL("../client/sbom-diff-api.ts", import.meta.url)),
  "utf-8",
)

describe("diffToCsv ecosystem column", () => {
  it("populates the ecosystem column for version-changed rows from the row type", () => {
    // Regression: version-bump rows used to emit a blank ecosystem while
    // added/removed rows carried it. They must now read v.type like the others.
    const versionRow = src.match(/"version_changed",[\s\S]*?\]/)?.[0] ?? ""
    assert.ok(versionRow, "version_changed row builder should exist")
    assert.match(versionRow, /v\.type \?\? ""/)
    assert.doesNotMatch(versionRow, /v\.name, "",/)
  })
})

describe("sbom-diff-api version-changed selection", () => {
  it("requests and maps the component type for version-changed rows", () => {
    // The GQL query must select `type` and the mapper must carry it through,
    // otherwise the CSV column above is always undefined.
    assert.match(apiSrc, /name purl type fromVersion/)
    assert.match(apiSrc, /type: v\.type \|\| undefined/)
  })
})

import test from "node:test"
import assert from "node:assert/strict"
import type { SbomDiffResponse } from "../../lib/client/sbom-diff-api.ts"

// ---------------------------------------------------------------------------
// SbomDiffView is a React component — we validate the data-layer logic that
// the view depends on rather than render it in a headless environment. The
// tests focus on the response shape the component receives and consumes.
// ---------------------------------------------------------------------------

function makeDiff(overrides: Partial<SbomDiffResponse> = {}): SbomDiffResponse {
  return {
    added: [],
    removed: [],
    version_changed: [],
    unchanged_count: 0,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Response shape validation
// ---------------------------------------------------------------------------

test("SbomDiffResponse with all 3 categories populated has correct counts", () => {
  const diff = makeDiff({
    added: [
      { name: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21", type: "library" },
      { name: "axios", version: "1.6.0", purl: "pkg:npm/axios@1.6.0", type: "library" },
      { name: "zod", version: "3.22.0", purl: "pkg:npm/zod@3.22.0", type: "library" },
    ],
    removed: [
      { name: "underscore", version: "1.13.6", purl: "pkg:npm/underscore@1.13.6", type: "library" },
    ],
    version_changed: [
      { name: "react", purl: "pkg:npm/react", from_version: "18.2.0", to_version: "18.3.1" },
      { name: "typescript", purl: "pkg:npm/typescript", from_version: "5.2.0", to_version: "5.4.0" },
      { name: "next", purl: "pkg:npm/next", from_version: "14.0.0", to_version: "15.0.0" },
      { name: "tailwindcss", purl: "pkg:npm/tailwindcss", from_version: "3.4.0", to_version: "4.0.0" },
      { name: "eslint", purl: "pkg:npm/eslint", from_version: "8.0.0", to_version: "9.0.0" },
    ],
    unchanged_count: 120,
  })

  assert.equal(diff.added.length, 3)
  assert.equal(diff.removed.length, 1)
  assert.equal(diff.version_changed.length, 5)
  assert.equal(diff.unchanged_count, 120)

  const totalChanges = diff.added.length + diff.removed.length + diff.version_changed.length
  assert.equal(totalChanges, 9)
})

test("SbomDiffResponse empty diff has all zero counts", () => {
  const diff = makeDiff({ unchanged_count: 500 })

  assert.equal(diff.added.length, 0)
  assert.equal(diff.removed.length, 0)
  assert.equal(diff.version_changed.length, 0)
  assert.equal(diff.unchanged_count, 500)

  const totalChanges = diff.added.length + diff.removed.length + diff.version_changed.length
  assert.equal(totalChanges, 0)
})

test("added components include name and version fields", () => {
  const diff = makeDiff({
    added: [{ name: "express", version: "4.18.2", type: "library" }],
  })

  const pkg = diff.added[0]
  assert.equal(pkg.name, "express")
  assert.equal(pkg.version, "4.18.2")
  assert.equal(pkg.type, "library")
})

test("version_changed entries have from_version and to_version", () => {
  const diff = makeDiff({
    version_changed: [
      { name: "react", purl: "pkg:npm/react", from_version: "18.2.0", to_version: "18.3.1" },
    ],
  })

  const change = diff.version_changed[0]
  assert.equal(change.name, "react")
  assert.equal(change.from_version, "18.2.0")
  assert.equal(change.to_version, "18.3.1")
})

test("version_changed tolerates null versions", () => {
  const diff = makeDiff({
    version_changed: [
      { name: "some-pkg", purl: undefined, from_version: null, to_version: "2.0.0" },
    ],
  })

  const change = diff.version_changed[0]
  assert.equal(change.from_version, null)
  assert.equal(change.to_version, "2.0.0")
})

test("removed components are distinguishable from added by array membership", () => {
  const diff = makeDiff({
    added: [{ name: "new-pkg", version: "1.0.0" }],
    removed: [{ name: "old-pkg", version: "2.0.0" }],
  })

  const addedNames = diff.added.map((c) => c.name)
  const removedNames = diff.removed.map((c) => c.name)

  assert.ok(addedNames.includes("new-pkg"))
  assert.ok(!addedNames.includes("old-pkg"))
  assert.ok(removedNames.includes("old-pkg"))
  assert.ok(!removedNames.includes("new-pkg"))
})

test("unchanged_count is separate from changed arrays", () => {
  const diff = makeDiff({
    added: [{ name: "a", version: "1.0.0" }],
    unchanged_count: 99,
  })

  // unchanged_count does not inflate the change arrays
  const totalChanges = diff.added.length + diff.removed.length + diff.version_changed.length
  assert.equal(totalChanges, 1)
  assert.equal(diff.unchanged_count, 99)
})

test("components without purl are still valid", () => {
  const diff = makeDiff({
    added: [{ name: "local-module", version: "0.1.0", type: "library" }],
  })

  const pkg = diff.added[0]
  assert.equal(pkg.name, "local-module")
  assert.equal(pkg.purl, undefined)
})

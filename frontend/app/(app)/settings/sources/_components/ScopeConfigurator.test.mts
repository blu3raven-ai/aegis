import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./ScopeConfigurator.tsx", import.meta.url)),
  "utf-8",
)

describe("ScopeConfigurator", () => {
  it("offers a cherry-pick 'selected' scope mode", () => {
    assert.match(src, /value="selected"/)
    assert.match(src, /Scan only selected/)
  })

  it("edits includedItems in selected mode (checked = included)", () => {
    assert.match(src, /function toggleIncluded/)
    assert.match(src, /onIncludedChange/)
    assert.match(src, /selectMode\s*\?\s*includedItems\.includes/)
  })

  it("still supports exclude mode on the same list shell", () => {
    assert.match(src, /toggleExcluded/)
    assert.match(src, /scanScope === "all-except-excluded" \|\| scanScope === "selected"/)
  })

  it("renders selections not in the discovered list (e.g. added by URL)", () => {
    // The list must union availableItems with included/excluded so a URL-added
    // repo that isn't among the discovered items still gets a checkable row.
    assert.match(src, /new Set\(\[\.\.\.\(availableItems \?\? \[\]\), \.\.\.includedItems, \.\.\.excludedItems\]\)/)
    assert.match(src, /const hasItems = sortedItems\.length > 0/)
  })

  it("pins added-by-URL items above the discovered list", () => {
    // Sort ranks non-discovered items first (rank < 0) so a URL-added repo floats
    // to the top instead of alphabetising into the middle of the discovered list.
    assert.match(src, /const rank = Number\(discovered\.has\(a\)\) - Number\(discovered\.has\(b\)\)/)
    assert.match(src, /rank !== 0 \? rank : a\.localeCompare\(b\)/)
  })
})

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
})

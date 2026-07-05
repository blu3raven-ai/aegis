import test from "node:test"
import assert from "node:assert/strict"
import { nextRovingIndex } from "../../frontend/lib/ui/menu-nav.ts"

// ---------------------------------------------------------------------------
// nextRovingIndex drives roving-tabindex arrow navigation for the SBOM export
// menu (and any vertical menu). It returns the next active index, or null for
// non-navigation keys so the caller lets them through.
// ---------------------------------------------------------------------------

const N = 4 // the export menu has four formats

test("ArrowDown advances and wraps from the last item to the first", () => {
  assert.equal(nextRovingIndex("ArrowDown", 0, N), 1)
  assert.equal(nextRovingIndex("ArrowDown", 2, N), 3)
  assert.equal(nextRovingIndex("ArrowDown", 3, N), 0)
})

test("ArrowUp retreats and wraps from the first item to the last", () => {
  assert.equal(nextRovingIndex("ArrowUp", 3, N), 2)
  assert.equal(nextRovingIndex("ArrowUp", 1, N), 0)
  assert.equal(nextRovingIndex("ArrowUp", 0, N), 3)
})

test("Home and End jump to the first and last item", () => {
  assert.equal(nextRovingIndex("Home", 2, N), 0)
  assert.equal(nextRovingIndex("End", 1, N), N - 1)
})

test("non-navigation keys return null so the caller ignores them", () => {
  assert.equal(nextRovingIndex("Enter", 1, N), null)
  assert.equal(nextRovingIndex("a", 1, N), null)
  assert.equal(nextRovingIndex("Escape", 1, N), null)
  assert.equal(nextRovingIndex("Tab", 1, N), null)
})

test("an empty menu yields null for every key (no divide-by-zero / NaN)", () => {
  for (const key of ["ArrowDown", "ArrowUp", "Home", "End"]) {
    assert.equal(nextRovingIndex(key, 0, 0), null)
  }
})

test("single-item menu always resolves back to index 0", () => {
  assert.equal(nextRovingIndex("ArrowDown", 0, 1), 0)
  assert.equal(nextRovingIndex("ArrowUp", 0, 1), 0)
  assert.equal(nextRovingIndex("End", 0, 1), 0)
})

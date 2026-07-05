import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./SaveViewModal.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("SaveViewModal", () => {
  it("accepts open, onClose, currentUrlState, onSaved", () => {
    assert.match(src, /open:\s*boolean/)
    assert.match(src, /onClose:\s*\(\)\s*=>\s*void/)
    assert.match(src, /currentUrlState:\s*Record<string, string>/)
    assert.match(src, /onSaved:\s*\(view:\s*SavedView\)\s*=>\s*void/)
  })

  it("calls createSavedView with surface=findings on submit", () => {
    assert.match(src, /createSavedView\(\{/)
    assert.match(src, /surface:\s*"findings"/)
  })

  it("disables Save when name is empty (trimmed)", () => {
    assert.match(src, /disabled=\{!name\.trim\(\) \|\| saving\}/)
  })
})

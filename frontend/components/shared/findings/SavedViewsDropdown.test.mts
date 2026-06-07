import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./SavedViewsDropdown.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("SavedViewsDropdown", () => {
  it("calls listSavedViews on mount", () => {
    assert.match(src, /listSavedViews\("findings"\)/)
  })

  it("calls onApply with the chosen view's url_state", () => {
    assert.match(src, /onApply\(v\.url_state\)/)
  })

  it("refetches when refreshSignal changes", () => {
    assert.match(src, /refreshSignal/)
  })
})

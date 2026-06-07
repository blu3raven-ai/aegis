import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingAssigneeEditor.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingAssigneeEditor", () => {
  it("declares props for findingId, currentAssignee, onUpdate", () => {
    assert.match(src, /findingId:\s*string/)
    assert.match(src, /currentAssignee:\s*string \| null/)
    assert.match(src, /onUpdate:\s*\(next:\s*string \| null\)\s*=>\s*void/)
  })

  it("calls updateFindingAssignee with null to clear assignment", () => {
    assert.match(src, /updateFindingAssignee\(numericId,\s*next\)/)
    assert.match(src, /onClick=\{\(\)\s*=>\s*commit\(null\)\}/)
  })

  it("trims whitespace and converts empty input to null", () => {
    assert.match(src, /input\.trim\(\)\s*\|\|\s*null/)
  })

  it("shows Unassigned label when currentAssignee is null", () => {
    assert.match(src, /currentAssignee\s*\?\?\s*"Unassigned"/)
  })

  it("renders a Clear button only when an assignee is set", () => {
    assert.match(src, /\{currentAssignee\s*&&\s*\(/)
    assert.match(src, />\s*Clear\s*</)
  })

  it("closes on outside click and Escape", () => {
    assert.match(src, /addEventListener\("mousedown"/)
    assert.match(src, /e\.key === "Escape"/)
  })

  it("disables Save while saving and shows Saving… label", () => {
    assert.match(src, /disabled=\{saving\}/)
    assert.match(src, /Saving…/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})

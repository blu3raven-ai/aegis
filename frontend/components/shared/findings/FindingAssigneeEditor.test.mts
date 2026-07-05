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

  it("delegates the picker UI to FindingAssigneePicker", () => {
    assert.match(src, /import \{ FindingAssigneePicker \}/)
    assert.match(src, /<FindingAssigneePicker/)
  })

  it("calls updateFindingAssignee with the picker's next value", () => {
    assert.match(src, /updateFindingAssignee\(numericId,\s*next\)/)
    assert.match(src, /onChange=\{\(next\)\s*=>\s*void commit\(next\)\}/)
  })

  it("shows the Unassigned label when no assignee is set", () => {
    assert.match(src, /emptyLabel="Unassigned"/)
  })

  it("disables the picker while a save is in flight", () => {
    assert.match(src, /disabled=\{saving\}/)
  })

  it("skips the save when next equals currentAssignee", () => {
    assert.match(src, /\(currentAssignee\s*\?\?\s*null\)\s*===\s*next/)
  })

  it("surfaces error text via role=alert", () => {
    assert.match(src, /role="alert"/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})

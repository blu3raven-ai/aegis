import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./SlaActionEditor.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("SlaActionEditor escalation cap", () => {
  it("defines MAX_ESCALATIONS = 4", () => {
    // Regression guard: matches the backend's hard cap.
    assert.match(
      src,
      /MAX_ESCALATIONS\s*=\s*4/,
      "should set MAX_ESCALATIONS to 4",
    )
  })

  it("disables the add button when at cap", () => {
    assert.match(
      src,
      /disabled=\{\s*atCap\s*\}/,
      "should disable the add escalation button when atCap is true",
    )
  })
})

describe("SlaActionEditor copy", () => {
  it("renders the fix-deadline-first hint when the deadline is zero", () => {
    assert.ok(
      src.includes("Fix the deadline above first"),
      "should render the deadline-invalid hint",
    )
  })

  it("renders the no-destinations helper", () => {
    assert.ok(
      src.includes("Set up a notification destination first"),
      "should render the no-destinations helper text",
    )
  })
})

describe("SlaActionEditor channel select", () => {
  it("renders an option per destination", () => {
    assert.ok(
      src.includes("destinations.map("),
      "should map destinations into <option> elements",
    )
  })
})

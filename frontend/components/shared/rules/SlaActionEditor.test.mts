import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./SlaActionEditor.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("SlaActionEditor escalations", () => {
  it("marks escalations as coming soon", () => {
    // Escalations persist but never deliver a notification, so the editor
    // presents them as a coming-soon leg rather than an interactive control.
    assert.ok(
      src.includes("Coming soon"),
      "should badge the escalations section as coming soon",
    )
  })

  it("does not offer an add-escalation control", () => {
    assert.ok(
      !src.includes("Add escalation step"),
      "the add-escalation button should be removed",
    )
  })

  it("still keeps the deadline as the working control", () => {
    assert.ok(
      src.includes("updateDeadline"),
      "the deadline control remains functional",
    )
  })
})

describe("SlaActionEditor grandfathered escalations", () => {
  it("renders any existing escalations read-only", () => {
    assert.ok(
      src.includes("before deadline") && src.includes("paused"),
      "existing escalations should render as read-only, paused rows",
    )
  })
})

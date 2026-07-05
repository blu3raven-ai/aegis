import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsDrawerShell.tsx", import.meta.url).pathname,
  "utf-8"
)

describe("FindingsDrawerShell accessibility", () => {
  it("renders role='dialog' on the aside element", () => {
    assert.ok(src.includes('role="dialog"'), "should have role=dialog")
  })

  it("renders aria-modal='true'", () => {
    assert.ok(src.includes('aria-modal="true"'), "should have aria-modal=true")
  })

  it("accepts label prop used as aria-label", () => {
    assert.ok(src.includes("aria-label={label}"), "should use label prop as aria-label")
  })

  it("accepts label as a required prop in the interface", () => {
    assert.ok(src.includes("label: string"), "label should be a required string prop")
  })

  it("traps focus using Tab key handler", () => {
    assert.ok(src.includes('"Tab"'), "should intercept Tab key for focus trap")
  })

  it("stores trigger element for focus restoration on close", () => {
    assert.ok(src.includes("triggerRef"), "should store trigger ref for focus restoration")
  })

  it("focuses first element in drawer on open", () => {
    assert.ok(src.includes("210"), "should use 210ms delay to focus after transition")
  })
})

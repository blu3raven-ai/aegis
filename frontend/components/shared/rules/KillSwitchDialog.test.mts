import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./KillSwitchDialog.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("KillSwitchDialog client directive", () => {
  it('has "use client" at the top', () => {
    assert.ok(src.startsWith('"use client"'), 'should start with "use client"')
  })
})

describe("KillSwitchDialog typed-confirmation gate", () => {
  it('requires the exact phrase "kill auto-dismiss"', () => {
    assert.ok(
      src.includes('"kill auto-dismiss"'),
      'should use "kill auto-dismiss" as the required confirmation phrase',
    )
  })

  it("trims the typed input before comparison", () => {
    assert.ok(src.includes("typed.trim()"), "should trim typed input before comparing")
  })

  it("does NOT lowercase — comparison is case-sensitive", () => {
    assert.ok(
      !src.includes(".toLowerCase()"),
      "gate must be case-sensitive — should not call toLowerCase",
    )
  })
})

describe("KillSwitchDialog Kill button styling", () => {
  it("uses the critical severity colour for the Kill button", () => {
    assert.ok(
      src.includes("var(--color-severity-critical)"),
      "should style the Kill button with the critical severity colour",
    )
  })
})

describe("KillSwitchDialog reason textarea", () => {
  it("provides a textarea for the kill-switch reason", () => {
    assert.ok(src.includes('id="kill-switch-reason"'), "should have the kill-switch reason textarea")
  })

  it("enforces maxLength of 500 on the reason textarea", () => {
    assert.ok(
      src.includes("maxLength={REASON_MAX}") || src.includes("maxLength={500}"),
      "should cap reason length at 500 characters",
    )
  })

  it("sets REASON_MAX to 500", () => {
    assert.ok(src.includes("const REASON_MAX = 500"), "REASON_MAX should be 500")
  })
})

describe("KillSwitchDialog ESC handling", () => {
  it("registers a keydown event listener", () => {
    assert.ok(
      src.includes('addEventListener("keydown"'),
      "should add a keydown event listener",
    )
  })

  it("closes on Escape key press", () => {
    assert.ok(
      src.includes('e.key === "Escape"'),
      'should handle the Escape key',
    )
  })
})

describe("KillSwitchDialog accessibility", () => {
  it('renders role="dialog"', () => {
    assert.ok(src.includes('role="dialog"'), 'should have role="dialog"')
  })

  it('renders aria-modal="true"', () => {
    assert.ok(src.includes('aria-modal="true"'), 'should have aria-modal="true"')
  })
})

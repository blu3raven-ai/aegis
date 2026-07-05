import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./AutoDismissActionEditor.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("AutoDismissActionEditor client directive", () => {
  it('has "use client" at the top', () => {
    assert.ok(src.startsWith('"use client"'), 'should start with "use client"')
  })
})

describe("AutoDismissActionEditor exports", () => {
  it("exports AUTO_DISMISS_DEFAULT constant", () => {
    assert.match(
      src,
      /export\s+const\s+AUTO_DISMISS_DEFAULT/,
      "should export AUTO_DISMISS_DEFAULT",
    )
  })
})

describe("AutoDismissActionEditor input fields", () => {
  it("contains a reason textarea field", () => {
    // The reason field uses an id and onChange that spreads into reason.
    assert.ok(src.includes('id="auto-dismiss-reason"'), "should have the reason textarea")
    assert.ok(
      src.includes("reason: e.target.value"),
      "should wire onChange to reason field",
    )
  })

  it("contains an audit_note textarea field", () => {
    assert.ok(src.includes('id="auto-dismiss-audit-note"'), "should have the audit_note textarea")
    assert.ok(
      src.includes("audit_note: e.target.value"),
      "should wire onChange to audit_note field",
    )
  })

  it("contains a rate_alarm_pct number input", () => {
    assert.ok(src.includes('id="auto-dismiss-rate-pct"'), "should have the rate_alarm_pct input")
    assert.ok(
      src.includes("rate_alarm_pct:"),
      "should wire onChange to rate_alarm_pct field",
    )
  })

  it("contains a rate_alarm_window_minutes number input", () => {
    assert.ok(
      src.includes('id="auto-dismiss-rate-window"'),
      "should have the rate_alarm_window_minutes input",
    )
    assert.ok(
      src.includes("rate_alarm_window_minutes:"),
      "should wire onChange to rate_alarm_window_minutes field",
    )
  })
})

describe("AutoDismissActionEditor onChange propagation", () => {
  it("calls onChange when reason changes", () => {
    assert.match(
      src,
      /onChange=\{\(e\)\s*=>\s*onChange\(\{[\s\S]*?reason:\s*e\.target\.value/,
      "should call onChange with updated reason",
    )
  })

  it("calls onChange when audit_note changes", () => {
    assert.match(
      src,
      /onChange=\{\(e\)\s*=>\s*onChange\(\{[\s\S]*?audit_note:\s*e\.target\.value/,
      "should call onChange with updated audit_note",
    )
  })

  it("calls onChange when rate_alarm_pct changes", () => {
    assert.match(
      src,
      /onChange=\{\(e\)\s*=>\s*\{[\s\S]*?rate_alarm_pct:/,
      "should call onChange with updated rate_alarm_pct",
    )
  })

  it("calls onChange when rate_alarm_window_minutes changes", () => {
    assert.match(
      src,
      /onChange=\{\(e\)\s*=>\s*\{[\s\S]*?rate_alarm_window_minutes:/,
      "should call onChange with updated rate_alarm_window_minutes",
    )
  })
})

describe("AutoDismissActionEditor rate alarm caption", () => {
  it("labels the rate alarm as a safety net", () => {
    assert.ok(src.includes("safety net"), 'should mention "safety net" in rate alarm section')
  })

  it("explains that the rule will automatically disable itself", () => {
    assert.ok(
      src.includes("automatically disable"),
      "should explain the auto-disable behaviour",
    )
  })
})

describe("AutoDismissActionEditor reason textarea", () => {
  it("has a placeholder that references auto-dismissed test fixtures", () => {
    assert.ok(
      src.includes("Auto-dismissed: test fixtures excluded"),
      "should have the expected placeholder text for reason",
    )
  })
})

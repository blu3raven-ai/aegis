import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./DataRetentionActionEditor.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("DataRetentionActionEditor type selector", () => {
  it("offers a radio for archive and delete", () => {
    assert.ok(src.includes('checked={value.type === "archive"}'))
    assert.ok(src.includes('checked={value.type === "delete"}'))
  })

  it("resets to delete-floor default when switching to delete with a sub-floor value", () => {
    // Regression guard: switching archive→delete with after_days below the
    // 90-day delete floor must fall back to the delete default rather than
    // silently keep an invalid value.
    assert.match(src, /switchType[\s\S]*next === "archive"/)
    assert.match(src, /switchType[\s\S]*DELETE_DEFAULT\.after_days/)
    assert.match(src, /value\.after_days\s*>=\s*DELETE_MIN_DAYS/)
  })

  it("exports ARCHIVE_DEFAULT for reuse by the modal", () => {
    assert.match(src, /export\s+const\s+ARCHIVE_DEFAULT/)
  })

  it("keeps DELETE_DEFAULT local (not exported)", () => {
    // Regression guard: the modal flow seeds archive on creation; delete
    // is opt-in via the editor only.
    assert.doesNotMatch(src, /export\s+const\s+DELETE_DEFAULT/)
    assert.match(src, /const\s+DELETE_DEFAULT/)
  })
})

describe("DataRetentionActionEditor delete warning", () => {
  it("shows the irreversible warning when delete is selected", () => {
    assert.ok(src.includes('value.type === "delete"'))
    assert.ok(src.includes("deleting scan results is"))
    assert.ok(src.includes("permanent"))
  })

  it("uses the critical color tokens on the warning panel", () => {
    assert.match(src, /color-severity-critical/)
  })

  it("wraps the warning in role=\"alert\" for screen readers", () => {
    assert.ok(src.includes('role="alert"'))
  })
})

describe("DataRetentionActionEditor day-input bounds", () => {
  it("constrains archive to a minimum of 30 days", () => {
    assert.match(src, /min=\{value\.type === "delete" \? DELETE_MIN_DAYS : ARCHIVE_MIN_DAYS\}/)
    assert.match(src, /ARCHIVE_MIN_DAYS\s*=\s*30/)
  })

  it("constrains delete to a minimum of 90 days", () => {
    assert.match(src, /DELETE_MIN_DAYS\s*=\s*90/)
  })

  it("constrains both action types to a maximum of 3650 days", () => {
    assert.match(src, /MAX_DAYS\s*=\s*3650/)
    assert.match(src, /max=\{MAX_DAYS\}/)
  })

  it("shows the active minimum in an inline hint", () => {
    assert.ok(src.includes("Must be at least"))
  })

  it("renders an aria-invalid error when the value falls outside bounds", () => {
    assert.match(src, /aria-invalid=\{daysInvalid\}/)
    assert.ok(src.includes("Enter a whole number between"))
  })
})

describe("DataRetentionActionEditor accessibility", () => {
  it('wraps the type selector with role="radiogroup"', () => {
    assert.ok(src.includes('role="radiogroup"'))
  })

  it("uses sr-only on the radio inputs", () => {
    assert.ok(src.includes('className="sr-only"'))
  })
})

describe("DataRetentionActionEditor isolation from notifications", () => {
  it("does not import notification destinations", () => {
    // Regression guard: data retention has no channels — surfacing
    // destination state here would mislead users and tangle the modal.
    assert.doesNotMatch(src, /NotificationDestination/)
    assert.doesNotMatch(src, /destinations-api/)
  })

  it("accepts only value and onChange in its props", () => {
    assert.match(
      src,
      /interface\s+DataRetentionActionEditorProps\s*\{[\s\S]*?value:\s*DataRetentionAction[\s\S]*?onChange:[\s\S]*?\}/,
    )
    assert.doesNotMatch(src, /destinations:\s*NotificationDestination/)
  })
})

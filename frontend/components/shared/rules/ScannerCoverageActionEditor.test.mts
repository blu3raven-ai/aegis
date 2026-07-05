import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ScannerCoverageActionEditor.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ScannerCoverageActionEditor type selector", () => {
  it("offers a radio for require_scanners and stale_alert", () => {
    assert.ok(src.includes('checked={value.type === "require_scanners"}'))
    assert.ok(src.includes('checked={value.type === "stale_alert"}'))
  })

  it("resets to defaults when the action type switches", () => {
    // Regression guard: switching action type clears unrelated fields.
    assert.match(src, /switchType[\s\S]*next === "require_scanners"[\s\S]*REQUIRE_DEFAULT/)
    assert.match(src, /switchType[\s\S]*REQUIRE_DEFAULT[\s\S]*STALE_DEFAULT/)
  })

  it("exports REQUIRE_DEFAULT for reuse by the modal", () => {
    // Regression guard: the modal imports this constant.
    assert.match(src, /export\s+const\s+REQUIRE_DEFAULT/)
  })
})

describe("ScannerCoverageActionEditor require_scanners fields", () => {
  it("offers all four scanner types as checkboxes", () => {
    for (const tool of ["dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning"]) {
      assert.ok(src.includes(`"${tool}"`), `should include scanner option ${tool}`)
    }
  })

  it("shows an error when no scanners are selected", () => {
    assert.ok(src.includes("Select at least one scanner"))
  })

  it("uses checkbox inputs (not radios) for the scanner list", () => {
    assert.match(src, /type="checkbox"[\s\S]*?onChange=\{\(\)\s*=>\s*toggle/)
  })
})

describe("ScannerCoverageActionEditor stale_alert fields", () => {
  it("constrains stale_after_days to 1–365", () => {
    assert.match(src, /min=\{1\}[\s\S]{0,500}max=\{365\}/)
  })

  it("marks alert delivery and auto-retrigger as coming soon", () => {
    // Neither the notify channel nor auto-retrigger is wired to a delivery
    // path, so they are presented as coming-soon rather than interactive.
    assert.ok(src.includes("Coming soon"), "should badge the delivery leg as coming soon")
    assert.ok(!src.includes("<Select"), "the channel <Select> should be removed")
    assert.ok(
      !src.includes("Also re-trigger a scan"),
      "the auto_retrigger checkbox should be removed",
    )
  })
})

describe("ScannerCoverageActionEditor accessibility", () => {
  it('wraps the type selector with role="radiogroup"', () => {
    assert.ok(src.includes('role="radiogroup"'))
  })

  it("uses sr-only on the radio inputs for visually-hidden but keyboard-accessible", () => {
    assert.ok(src.includes('className="sr-only"'))
  })
})

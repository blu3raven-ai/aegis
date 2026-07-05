import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RulePreview.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("RulePreview create-mode guard", () => {
  it("early-returns from the effect when ruleId is null", () => {
    // Regression guard: don't fire preview requests when the rule has
    // not been persisted yet (create mode).
    assert.match(
      src,
      /if\s*\(\s*ruleId\s*===\s*null\s*\)\s*return/,
      "should bail out of the effect when ruleId === null",
    )
  })

  it("renders the save-first empty state when ruleId is null", () => {
    assert.ok(
      src.includes("Save the rule first to dry-run it"),
      "should render the create-mode empty state copy",
    )
  })
})

describe("RulePreview stub notice", () => {
  it("renders the P1 backend stub notice", () => {
    assert.ok(
      src.includes("P1 backend preview is currently a stub"),
      "should render the stub notice copy",
    )
  })
})

describe("RulePreview match count copy", () => {
  it("renders the zero-match copy", () => {
    assert.ok(
      src.includes("No findings match"),
      "should render the no-findings copy",
    )
  })

  it("renders the single-match copy", () => {
    assert.ok(
      src.includes("1 finding would match"),
      "should render the single-match copy",
    )
  })

  it("renders the plural-match template", () => {
    assert.ok(
      src.includes("findings would match"),
      "should render the plural-match copy",
    )
  })
})

describe("RulePreview retry affordance", () => {
  it("labels the retry button for screen readers", () => {
    assert.ok(
      src.includes('aria-label="Retry preview"'),
      "should expose the retry button to assistive tech",
    )
  })
})

describe("RulePreview effect cleanup", () => {
  it("guards async results behind a cancelled flag", () => {
    // Regression guard: prevents setState on stale promises after the
    // effect re-runs or the component unmounts.
    assert.match(
      src,
      /let\s+cancelled\s*=\s*false/,
      "should declare a cancelled flag",
    )
    assert.match(
      src,
      /cancelled\s*=\s*true/,
      "should flip the cancelled flag in cleanup",
    )
  })
})

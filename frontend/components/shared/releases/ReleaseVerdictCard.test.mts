import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ReleaseVerdictCard.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ReleaseVerdictCard verdict copy", () => {
  it("contains the no_go title", () => {
    assert.ok(
      src.includes("critical findings — not recommended for release"),
      "should render no_go title",
    )
  })

  it("contains the warn title", () => {
    assert.ok(
      src.includes("high findings — review before release"),
      "should render warn title",
    )
  })

  it("contains the go title", () => {
    assert.ok(
      src.includes("Cleared for release — no blockers"),
      "should render go title",
    )
  })

  it("contains the pending title", () => {
    assert.ok(src.includes("Scan in progress"), "should render pending title")
  })

  it("contains the unknown title", () => {
    assert.ok(
      src.includes("Verdict unavailable — re-run scan to compute"),
      "should render unknown title",
    )
  })
})

describe("ReleaseVerdictCard action buttons", () => {
  it("conditionally hides Create Jira ticket when verdict is go", () => {
    // Regression guard: the Jira button must remain gated on the verdict
    // not being "go" — accidentally inverting or dropping this check would
    // surface the remediation CTA on releases that are already cleared.
    const gatePattern = /release\.verdict\s*!==\s*["']go["']/
    assert.match(
      src,
      gatePattern,
      "should gate Jira ticket button on verdict !== 'go'",
    )
  })

  it("renders empty state when release is null", () => {
    assert.ok(
      src.includes("Run a scan to see the verdict"),
      "should render empty-state copy",
    )
  })
})

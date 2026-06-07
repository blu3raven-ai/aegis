import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsMoreFiltersPopover.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsMoreFiltersPopover", () => {
  it("declares FindingsMoreFiltersValues with cwe, kev, epssMin, riskScoreMin, assigneeUserId", () => {
    assert.match(src, /cwe:\s*string \| null/)
    assert.match(src, /kev:\s*boolean/)
    assert.match(src, /epssMin:\s*number \| null/)
    assert.match(src, /riskScoreMin:\s*number \| null/)
    assert.match(src, /assigneeUserId:\s*string \| null/)
  })

  it("renders a Risk score ≥ numeric input bound to riskScoreMin", () => {
    assert.match(src, /Risk score ≥/)
    assert.match(src, /riskScoreMin/)
    assert.match(src, /min=\{0\}\s+max=\{100\}/)
  })

  it("delegates Assignee selection to FindingAssigneePicker", () => {
    assert.match(src, /import\s*\{\s*FindingAssigneePicker\s*\}/)
    assert.match(src, /<FindingAssigneePicker[\s\S]*?label="Assignee"/)
    assert.match(src, /value=\{values\.assigneeUserId\}/)
    assert.match(src, /onChange=\{\(next\)\s*=>\s*onChange\(\{ assigneeUserId: next \}\)\}/)
  })

  it("renders the trigger chip with an active count when filters are set", () => {
    assert.match(src, /activeCount/)
    assert.match(src, /activeCount\s*>\s*0/)
  })

  it("closes on outside click via mousedown listener", () => {
    assert.match(src, /addEventListener\("mousedown"/)
  })

  it("closes on Escape key", () => {
    assert.match(src, /e\.key === "Escape"/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})

import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RulesSummaryStrip.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("RulesSummaryStrip KPI labels", () => {
  it("renders the Active rules KPI", () => {
    assert.ok(src.includes("Active rules"), "should render Active rules label")
  })

  it("renders the SLA compliance KPI", () => {
    assert.ok(src.includes("SLA compliance"), "should render SLA compliance label")
  })

  it("renders the Violations open KPI", () => {
    assert.ok(src.includes("Violations open"), "should render Violations open label")
  })

  it("renders the Coverage gaps KPI", () => {
    assert.ok(src.includes("Coverage gaps"), "should render Coverage gaps label")
  })
})

describe("RulesSummaryStrip value formatting", () => {
  it("appends a percent sign to the SLA compliance value", () => {
    assert.match(
      src,
      /sla_compliance_pct\}%/,
      "should render the SLA compliance value with %",
    )
  })
})

describe("RulesSummaryStrip fallback notes", () => {
  it("renders the unavailable-stats note", () => {
    assert.ok(
      src.includes("Stats unavailable"),
      "should render the empty-state note",
    )
  })

  it("renders the loading note", () => {
    assert.ok(
      src.includes("Loading…"),
      "should render the loading note",
    )
  })
})

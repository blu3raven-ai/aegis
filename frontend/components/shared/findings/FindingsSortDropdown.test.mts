import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsSortDropdown.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsSortDropdown", () => {
  it("exports a SORT_OPTIONS list with the five sort keys", () => {
    assert.match(src, /SORT_OPTIONS:/)
    assert.match(src, /"severity_age"/)
    assert.match(src, /"epss"/)
    assert.match(src, /"risk_score"/)
    assert.match(src, /"newest"/)
    assert.match(src, /"oldest"/)
  })

  it("offers a Risk score option labelled high → low", () => {
    assert.match(src, /\{\s*value:\s*"risk_score",\s*label:\s*"Risk score \(high → low\)"\s*\}/)
  })

  it("accepts value and onChange", () => {
    assert.match(src, /value:\s*SortKey/)
    assert.match(src, /onChange:\s*\(next:\s*SortKey\)\s*=>\s*void/)
  })

  it("default option in SORT_OPTIONS is severity_age (Severity → Age)", () => {
    assert.match(src, /\{\s*value:\s*"severity_age",\s*label:\s*"Severity → Age"\s*\}/)
  })
})

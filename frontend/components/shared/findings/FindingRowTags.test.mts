import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingRowTags.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingRowTags", () => {
  it("accepts kev, epssPercentile, firstSeen, cwe props", () => {
    assert.match(src, /kev\?:\s*boolean/)
    assert.match(src, /epssPercentile\?:\s*number/)
    assert.match(src, /firstSeen\?:\s*string/)
    assert.match(src, /cwe\?:\s*string/)
  })

  it("renders KEV chip when kev=true", () => {
    assert.match(src, /\{kev && /)
  })

  it("renders EPSS chip when percentile >= 0.5", () => {
    assert.match(src, /epssPercentile.*0\.5/)
  })

  it("renders NEW chip when firstSeen is within last 7 days", () => {
    assert.match(src, /NEW_WINDOW_DAYS\s*=\s*7/)
  })

  it("renders CWE chip when cwe is set", () => {
    assert.match(src, /\{cwe && /)
  })

  it("uses text-2xs micro-label scale (CLAUDE.md typography)", () => {
    assert.match(src, /text-2xs/)
  })
})

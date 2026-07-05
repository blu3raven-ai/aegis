import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingRowTags.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingRowTags", () => {
  it("accepts kev, epssPercentile, firstSeen props", () => {
    assert.match(src, /kev\?:\s*boolean/)
    assert.match(src, /epssPercentile\?:\s*number/)
    assert.match(src, /firstSeen\?:\s*string/)
  })

  it("accepts a malicious prop", () => {
    assert.match(src, /malicious\?:\s*boolean/)
  })

  it("renders a Malware chip when malicious=true", () => {
    assert.match(src, /\{malicious && /)
    assert.match(src, /Malware/)
  })

  it("shows the Malware chip even without kev/epss/new signals", () => {
    assert.match(src, /if \(!malicious && !kev && !showEpss && !showNew\) return null/)
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

  it("uses text-2xs micro-label scale (CLAUDE.md typography)", () => {
    assert.match(src, /text-2xs/)
  })
})

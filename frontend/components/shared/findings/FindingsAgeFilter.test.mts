import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsAgeFilter.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsAgeFilter", () => {
  it("exports AGE_OPTIONS with preset values", () => {
    assert.match(src, /"any"/)
    assert.match(src, /"24h"/)
    assert.match(src, /"7d"/)
    assert.match(src, /"30d"/)
  })

  it("accepts value and onChange typed as AgePresetKey", () => {
    assert.match(src, /value:\s*AgePresetKey/)
    assert.match(src, /onChange:\s*\(next:\s*AgePresetKey\)\s*=>\s*void/)
  })

  it("exports presetToFirstSeenAfter for caller to convert to ISO", () => {
    assert.match(src, /export function presetToFirstSeenAfter/)
  })
})

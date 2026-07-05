import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { relativeTime } from "./relative-time.ts"

describe("relativeTime", () => {
  it("returns '—' for null", () => {
    assert.equal(relativeTime(null), "—")
  })

  it("returns '—' for undefined", () => {
    assert.equal(relativeTime(undefined), "—")
  })

  it("returns 'just now' for the current moment", () => {
    assert.equal(relativeTime(new Date().toISOString()), "just now")
  })

  it("returns minutes for a few minutes ago", () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString()
    assert.equal(relativeTime(fiveMinAgo), "5 minutes ago")
  })

  it("echoes the original string when input is unparseable", () => {
    assert.equal(relativeTime("not-a-date"), "not-a-date")
  })

  it("never reports '0 years ago' at the 360-364 day boundary", () => {
    const day = 86_400_000
    for (const days of [359, 360, 362, 364, 365, 366]) {
      const label = relativeTime(new Date(Date.now() - days * day).toISOString())
      assert.doesNotMatch(label, /\b0 years? ago\b/, `${days} days -> "${label}"`)
    }
    // Just under a year still reads in months; a full year reads as 1 year.
    assert.equal(relativeTime(new Date(Date.now() - 359 * day).toISOString()), "11 months ago")
    assert.equal(relativeTime(new Date(Date.now() - 365 * day).toISOString()), "1 year ago")
  })
})

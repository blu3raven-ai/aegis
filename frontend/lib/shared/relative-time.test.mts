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
})

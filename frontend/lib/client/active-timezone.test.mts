import { describe, it, afterEach } from "node:test"
import assert from "node:assert/strict"

import { getActiveTimeZone, setActiveTimeZone } from "./active-timezone.ts"

afterEach(() => setActiveTimeZone(undefined))

describe("active-timezone", () => {
  it("defaults to undefined (runtime/browser zone) before anything is set", () => {
    assert.equal(getActiveTimeZone(), undefined)
  })

  it("stores a valid IANA zone", () => {
    setActiveTimeZone("Asia/Kuala_Lumpur")
    assert.equal(getActiveTimeZone(), "Asia/Kuala_Lumpur")
  })

  it("treats a blank/whitespace value as the runtime default", () => {
    setActiveTimeZone("America/New_York")
    setActiveTimeZone("   ")
    assert.equal(getActiveTimeZone(), undefined)
    setActiveTimeZone("America/New_York")
    setActiveTimeZone(null)
    assert.equal(getActiveTimeZone(), undefined)
  })

  it("rejects an unrecognised zone rather than storing a value that would throw at format time", () => {
    setActiveTimeZone("Mars/Olympus")
    assert.equal(getActiveTimeZone(), undefined)
    // And a stored-good value is not left behind after a bad set.
    setActiveTimeZone("UTC")
    setActiveTimeZone("Not/AZone")
    assert.equal(getActiveTimeZone(), undefined)
  })

  it("produces a zone that Intl can actually format with", () => {
    setActiveTimeZone("Asia/Tokyo")
    const formatted = new Date("2026-07-02T00:00:00Z").toLocaleString("en-US", {
      timeZone: getActiveTimeZone(),
      hour: "2-digit",
      hour12: false,
    })
    // 00:00 UTC is 09:00 in Tokyo (UTC+9).
    assert.match(formatted, /09/)
  })
})

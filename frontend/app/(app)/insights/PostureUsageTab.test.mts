import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./PostureUsageTab.tsx", import.meta.url)),
  "utf-8",
)

describe("PostureUsageTab", () => {
  it("only blanks the tab when the initial load fails (no data yet)", () => {
    // A transient failure while switching ranges must keep the last-good
    // window on screen, so the full-page error is gated on usage === null.
    assert.match(src, /state === "error" && usage === null/)
  })

  it("shows a non-destructive inline error when a refresh fails with data on screen", () => {
    assert.match(src, /\{state === "error" && \(/)
    assert.match(src, /Showing the last loaded window/)
  })

  it("retries via a refresh nonce, not a full page reload", () => {
    assert.match(src, /setRefreshKey\(\(k\) => k \+ 1\)/)
    assert.match(src, /\}, \[days, refreshKey\]\)/)
    assert.doesNotMatch(src, /window\.location\.reload/)
  })

  it("polls in the background and refetches on focus so usage stays live", () => {
    // Verification usage only lands when a scan finishes ingesting, so the tab
    // must refresh itself rather than show a stale 0 until a manual reload.
    assert.match(src, /window\.setInterval\(refresh, 15000\)/)
    assert.match(src, /window\.addEventListener\("focus", refresh\)/)
    assert.match(src, /window\.removeEventListener\("focus", refresh\)/)
  })
})

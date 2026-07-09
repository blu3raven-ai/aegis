import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./ScanProgressProvider.tsx", import.meta.url)),
  "utf-8",
)

describe("ScanProgressProvider", () => {
  it("exposes a dismiss() that hides a banner without cancelling the scan", () => {
    assert.match(src, /dismiss: \(connectionId: string\) => void/)
    assert.match(src, /dismissedRef\.current\.add\(connectionId\)/)
  })

  it("keeps a dismissed banner hidden against the re-discovery poll", () => {
    // The 10s discover poll must skip connections the user dismissed, or the
    // banner would pop straight back.
    assert.match(src, /if \(dismissedRef\.current\.has\(scan\.connectionId\)\) continue/)
  })

  it("clears a dismissal once the connection is no longer scanning", () => {
    // So the next scan on that connection is free to show a fresh banner.
    assert.match(src, /if \(!activeIds\.has\(id\)\) dismissedRef\.current\.delete\(id\)/)
  })
})

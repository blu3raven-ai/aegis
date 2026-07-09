import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./ScanRunningBanner.tsx", import.meta.url)),
  "utf-8",
)

describe("ScanRunningBanner", () => {
  it("renders a Dismiss control when onDismiss is provided (escape hatch)", () => {
    assert.match(src, /onDismiss\?: \(\) => void/)
    assert.match(src, /aria-label="Dismiss"/)
    assert.match(src, /onClick=\{onDismiss\}/)
  })

  it("uses plain-language stage labels, not scanner jargon", () => {
    assert.match(src, /ingesting: "Saving results"/)
    assert.match(src, /classifying: "Analysing findings"/)
    assert.doesNotMatch(src, /Ingesting scanner output/)
  })
})

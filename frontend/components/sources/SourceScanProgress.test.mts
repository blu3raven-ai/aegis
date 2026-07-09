import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./SourceScanProgress.tsx", import.meta.url)),
  "utf-8",
)

describe("SourceScanProgress", () => {
  it("reports honest overall progress, not an average of scanner percents", () => {
    // Finished scanners count fully, in-flight ones by their fraction, queued
    // ones as zero — so the bar tracks real completion of the whole run.
    assert.match(src, /finishedCount \+ activeFractionSum/)
    assert.doesNotMatch(src, /avgPercent/)
  })

  it("forwards a dismiss handler to the banner", () => {
    assert.match(src, /onDismiss\?: \(\) => void/)
    assert.match(src, /onDismiss=\{onDismiss\}/)
  })
})

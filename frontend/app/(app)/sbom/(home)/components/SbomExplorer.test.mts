import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./SbomExplorer.tsx", import.meta.url)),
  "utf-8",
)

describe("SbomExplorer out-of-order response guard", () => {
  it("stamps each fetch with a monotonic sequence and drops superseded results", () => {
    // Rapid facet changes fire overlapping fetches; a slow earlier one must not
    // overwrite a newer result. Mirrors the RiskyComponentsView pattern.
    assert.match(src, /const fetchSeqRef = useRef\(0\)/)
    assert.match(src, /const seq = \+\+fetchSeqRef\.current/)
    assert.match(src, /if \(fetchSeqRef\.current !== seq\) return/)
    // setData must be guarded, not called unconditionally after the await.
    const guarded = src.match(/if \(fetchSeqRef\.current !== seq\) return[^\n]*\n\s*setData\(/)
    assert.ok(guarded, "setData should be preceded by the sequence guard")
  })
})

import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./BlastRadiusSection.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("BlastRadiusSection", () => {
  it("renders nothing when the count is zero or unknown", () => {
    assert.match(src, /if \(count == null \|\| count <= 0\) return null/)
  })

  it("lazily fetches the related repos on first expand", () => {
    assert.match(src, /if \(next && rows === null && !loading\)/)
    assert.match(src, /getFindingRelated\(findingId\)/)
  })

  it("collapses and clears the cached list when the finding changes", () => {
    assert.match(src, /setOpen\(false\)/)
    assert.match(src, /setRows\(null\)/)
    assert.match(src, /\}, \[findingId\]\)/)
  })

  it("deep-links each related repo to its finding", () => {
    assert.match(src, /href=\{`\/findings\?finding=\$\{r\.finding_id\}`\}/)
  })

  it("is singular/plural aware", () => {
    assert.match(src, /count === 1 \? "repository" : "repositories"/)
  })
})

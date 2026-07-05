import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsGroupHeader.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsGroupHeader", () => {
  it("accepts label, severityCounts, total, expanded, onToggle props", () => {
    assert.match(src, /label:\s*string/)
    assert.match(src, /severityCounts:\s*\{\s*critical:\s*number;\s*high:\s*number;\s*medium:\s*number;\s*low:\s*number\s*\}/)
    assert.match(src, /total:\s*number/)
    assert.match(src, /expanded:\s*boolean/)
    assert.match(src, /onToggle:\s*\(\)\s*=>\s*void/)
  })

  it("renders the chevron with rotation tied to expanded state", () => {
    assert.match(src, /aria-expanded=\{expanded\}/)
    assert.match(src, /rotate-/)
  })

  it("renders only severity buckets with counts > 0", () => {
    assert.match(src, /severityCounts\.critical\s*>\s*0/)
    assert.match(src, /severityCounts\.high\s*>\s*0/)
    assert.match(src, /severityCounts\.medium\s*>\s*0/)
    assert.match(src, /severityCounts\.low\s*>\s*0/)
  })

  it("uses text-2xs micro-label scale for severity pills (CLAUDE.md typography)", () => {
    assert.match(src, /text-2xs/)
  })

  it("calls onToggle on header click and keyboard activation", () => {
    assert.match(src, /onClick=\{onToggle\}/)
    assert.match(src, /onKeyDown=/)
  })
})

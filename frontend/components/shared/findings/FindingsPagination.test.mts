import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsPagination.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsPagination", () => {
  it("renders 'Showing X-Y of N findings'", () => {
    assert.match(src, /Showing/)
    assert.match(src, /findings/)
  })

  it("computes totalPages from total + pageSize", () => {
    assert.match(src, /Math\.max\(1,\s*Math\.ceil\(total\s*\/\s*pageSize\)\)/)
  })

  it("disables prev when page <= 1 and next when page >= totalPages", () => {
    assert.match(src, /disabled=\{page\s*<=?\s*1\}/)
    assert.match(src, /disabled=\{page\s*>=?\s*totalPages\}/)
  })

  it("calls onChange with the next page number", () => {
    assert.match(src, /onChange\(page \+ 1\)/)
    assert.match(src, /onChange\(page - 1\)/)
  })

  it("windows visible pages around the current page", () => {
    assert.match(src, /WINDOW/)
  })
})

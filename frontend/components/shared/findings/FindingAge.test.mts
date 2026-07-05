import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./FindingAge.tsx", import.meta.url).pathname, "utf-8")

describe("FindingAge", () => {
  it("owns the never-wrap + tabular-nums invariant", () => {
    assert.match(src, /whitespace-nowrap tabular-nums/)
  })

  it("merges per-context styling via className", () => {
    assert.match(src, /className\?: string/)
    assert.match(src, /cn\("whitespace-nowrap tabular-nums", className\)/)
  })
})

import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./PageHeader.tsx", import.meta.url).pathname, "utf-8")

describe("PageHeader inline count", () => {
  it("accepts a count prop typed as number | null", () => {
    assert.match(src, /count\?:\s*number\s*\|\s*null/)
  })

  it("guards the count render with a typeof + isFinite check", () => {
    assert.match(src, /typeof count === "number"/)
    assert.match(src, /Number\.isFinite\(count\)/)
  })

  it("renders count.toLocaleString() inside an inline pill", () => {
    assert.match(src, /count\.toLocaleString\(\)/)
    assert.ok(src.includes("rounded-full"))
    assert.ok(src.includes("tabular-nums"))
  })

  it("keeps controls slot intact for right-aligned buttons", () => {
    assert.match(src, /controls\?:\s*React\.ReactNode/)
    assert.match(src, /\{controls\}/)
  })

  it("renders title in a flex baseline row so the pill aligns with the title", () => {
    assert.match(src, /<h1[^>]*flex[^>]*items-baseline/)
  })
})

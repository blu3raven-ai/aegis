import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(
  join(ROOT, "frontend/app/(app)/posture/PosturePageContent.tsx"),
  "utf8",
)

describe("PosturePageContent shell", () => {
  it("declares both tab values", () => {
    assert.match(src, /const TABS = \["summary", "breakdown"\] as const/)
  })

  it("uses the canonical underline tab style", () => {
    assert.match(
      src,
      /-mb-px border-b-2 px-3 py-2\.5 text-sm transition-colors/,
    )
  })

  it("delegates to PostureSummaryTab when active", () => {
    assert.match(src, /import \{ PostureSummaryTab \}/)
    assert.match(src, /<PostureSummaryTab/)
  })

  it("delegates to PostureBreakdownTab when active", () => {
    assert.match(src, /import \{ PostureBreakdownTab \}/)
    assert.match(src, /<PostureBreakdownTab/)
  })
})

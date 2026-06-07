import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(
  join(ROOT, "frontend/app/(app)/posture/PostureBreakdownTab.tsx"),
  "utf8",
)

describe("PostureBreakdownTab structure", () => {
  it("defines SeverityDonut", () => {
    assert.match(src, /function SeverityDonut\(/)
  })
  it("defines TopReposPanel", () => {
    assert.match(src, /function TopReposPanel\(/)
  })
  it("defines CoverageAndRemediation", () => {
    assert.match(src, /function CoverageAndRemediation\(/)
  })
  it("defines AgeBucketsPanel", () => {
    assert.match(src, /function AgeBucketsPanel\(/)
  })
  it("renders the four panels", () => {
    assert.match(src, /<SeverityDonut/)
    assert.match(src, /<TopReposPanel/)
    assert.match(src, /<CoverageAndRemediation/)
    assert.match(src, /<AgeBucketsPanel/)
  })
})

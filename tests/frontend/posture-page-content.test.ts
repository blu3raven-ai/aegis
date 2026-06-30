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
  // #986 collapsed the Summary/Breakdown tab split into one scrollable view,
  // so the shell no longer hosts a NavTabs switcher or a TABS list.
  it("renders one single-scroll view (no summary/breakdown tab switch)", () => {
    assert.doesNotMatch(src, /from "@\/components\/ui\/NavTabs"/)
    assert.doesNotMatch(src, /const TABS = /)
  })

  it("delegates the whole view to PostureSummaryTab", () => {
    assert.match(src, /import \{ PostureSummaryTab/)
    assert.match(src, /<PostureSummaryTab/)
  })

  it("loads the posture snapshot and trend series", () => {
    assert.match(src, /getPostureSnapshot\(/)
    assert.match(src, /getPostureTrend\(/)
  })

  it("falls back to the ghost preview when there is no data", () => {
    assert.match(src, /<PostureGhostPreview/)
  })
})

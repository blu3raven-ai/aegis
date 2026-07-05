import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
// The Summary/Breakdown tab split was collapsed into one single-scroll view
// (#986): the old PostureBreakdownTab became a panels module, and the summary
// view is now the one place that assembles those panels.
const panels = readFileSync(
  join(ROOT, "frontend/app/(app)/insights/PostureBreakdownPanels.tsx"),
  "utf8",
)
const summary = readFileSync(
  join(ROOT, "frontend/app/(app)/insights/PostureSummaryTab.tsx"),
  "utf8",
)

describe("PostureBreakdownPanels structure", () => {
  it("defines SeverityDonut", () => {
    assert.match(panels, /function SeverityDonut\(/)
  })
  it("defines TopReposPanel", () => {
    assert.match(panels, /function TopReposPanel\(/)
  })
  // Renamed from CoverageAndRemediation: the remediation block was dropped in
  // #986 (the MTTR + Resolved KPIs already cover it), leaving coverage only.
  it("defines RepositoryCoveragePanel", () => {
    assert.match(panels, /function RepositoryCoveragePanel\(/)
  })
  it("defines AgeBucketsPanel", () => {
    assert.match(panels, /function AgeBucketsPanel\(/)
  })
  it("the summary view renders all four panels", () => {
    assert.match(summary, /<SeverityDonut/)
    assert.match(summary, /<TopReposPanel/)
    assert.match(summary, /<RepositoryCoveragePanel/)
    assert.match(summary, /<AgeBucketsPanel/)
  })
})

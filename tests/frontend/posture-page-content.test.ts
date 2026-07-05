import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(
  join(ROOT, "frontend/app/(app)/insights/PosturePageContent.tsx"),
  "utf8",
)

describe("PosturePageContent shell", () => {
  // The posture surface is split into Overview + Triage tabs so an analyst can
  // move from the at-a-glance dashboard to a drill-down triage workspace. The
  // shell hosts a NavTabs switcher between the two views.
  it("renders an Overview/Triage tab switch via NavTabs", () => {
    assert.match(src, /from "@\/components\/ui\/NavTabs"/)
    assert.match(src, /label: "Overview"/)
    assert.match(src, /label: "Triage"/)
    assert.match(src, /<NavTabs/)
  })

  it("delegates to PostureSummaryTab for the Overview tab", () => {
    assert.match(src, /import \{ PostureSummaryTab/)
    assert.match(src, /<PostureSummaryTab/)
  })

  it("delegates to PostureTriageTab for the Triage tab", () => {
    assert.match(src, /import \{ PostureTriageTab/)
    assert.match(src, /<PostureTriageTab/)
  })

  it("delegates to PostureUsageTab for the Usage tab", () => {
    assert.match(src, /import \{ PostureUsageTab/)
    assert.match(src, /label: "Usage"/)
    assert.match(src, /<PostureUsageTab/)
  })

  it("gates the Usage tab on the manage_settings permission", () => {
    // The usage ledger endpoint is manage_settings-gated, so the tab must only
    // be offered to callers who can load it — not shown then 403'd.
    assert.match(src, /useHasPermission\("manage_settings"\)/)
    assert.match(src, /canViewUsage/)
    // A ?tab=usage deep-link a viewer can't see must fall back, not break.
    assert.match(src, /effectiveTab/)
  })

  it("loads the posture snapshot and trend series", () => {
    assert.match(src, /getPostureSnapshot\(/)
    assert.match(src, /getPostureTrend\(/)
  })

  it("loads the triage datasets (scanner breakdown, exploitability, SLA)", () => {
    assert.match(src, /getPostureScannerBreakdown\(/)
    assert.match(src, /getPostureExploitabilitySummary\(/)
    assert.match(src, /getPostureSlaPosture\(/)
  })

  it("falls back to the ghost preview when there is no data", () => {
    assert.match(src, /<PostureGhostPreview/)
  })
})

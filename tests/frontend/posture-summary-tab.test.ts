import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(
  join(ROOT, "frontend/app/(app)/posture/PostureSummaryTab.tsx"),
  "utf8",
)

describe("PostureSummaryTab — shared helpers", () => {
  it("defines SEV_VARS", () => {
    assert.match(src, /const SEV_VARS = \{/)
  })
  it("defines getRatingTokens", () => {
    assert.match(src, /function getRatingTokens\(/)
  })
  // sparkPath + the local Sparkline were extracted into a shared chart
  // primitive (#998); the summary now consumes it instead of defining it.
  it("imports the shared Sparkline primitive", () => {
    assert.match(
      src,
      /import \{ Sparkline \} from "@\/components\/shared\/charts\/Sparkline"/,
    )
  })
  it("uses the Sparkline primitive", () => {
    assert.match(src, /<Sparkline/)
  })
  it("defines DeltaBadge component", () => {
    assert.match(src, /function DeltaBadge\(/)
  })
  it("defines deriveDelta helper", () => {
    assert.match(src, /function deriveDelta\(/)
  })
})

describe("PostureSummaryTab — Beat 1: Hero", () => {
  it("defines RiskScoreHero", () => {
    assert.match(src, /function RiskScoreHero\(/)
  })
  // The sparkline window is now driven by the page time-range control, so the
  // card labels it "{range} trend" rather than a hardcoded 90-day window.
  it("RiskScoreHero shows the range-windowed trend sparkline inside the score card", () => {
    assert.match(
      src,
      /\{RANGE_LABEL\[rangeDays\]\} trend[\s\S]*?<Sparkline values=\{scoreSeries\}/,
    )
  })
  // #983 deliberately re-surfaced the already-computed risk-score summary on
  // the hero (the earlier redesign that dropped it was reversed).
  it("RiskScoreHero surfaces the risk-score summary", () => {
    assert.match(src, /riskScore\.summary/)
  })
  it("defines KpiCard", () => {
    assert.match(src, /function KpiCard\(/)
  })
  it("defines KpiGrid", () => {
    assert.match(src, /function KpiGrid\(/)
  })
  it("KpiGrid uses all four KPI labels", () => {
    assert.match(src, /Critical findings/)
    assert.match(src, /MTTR/)
    assert.match(src, /Resolved \(30d\)/)
    assert.match(src, /SLA attainment/)
  })
  // The one live metric from the removed integration strip (all-time resolved)
  // folded into the KPI grid (#983).
  it("KpiGrid surfaces all-time resolved via remediation totalFixed", () => {
    assert.match(src, /rem\.totalFixed/)
  })
  it("PostureSummaryTab body renders the hero grid", () => {
    assert.match(src, /<RiskScoreHero/)
    assert.match(src, /<KpiGrid/)
  })
})

describe("PostureSummaryTab — Beat 2: Attention", () => {
  it("defines AttentionPanel", () => {
    assert.match(src, /function AttentionPanel\(/)
  })
  it("includes an age-buckets fold-in row", () => {
    assert.match(src, /findings open over 90 days/)
  })
  it("body renders the AttentionPanel", () => {
    assert.match(src, /<AttentionPanel/)
  })
})

describe("PostureSummaryTab — Beat 4a: Trend chart", () => {
  it("defines PostureTrendChart", () => {
    assert.match(src, /function PostureTrendChart\(/)
  })
  it("uses stacked area paths (low/medium/high/critical fills)", () => {
    assert.match(src, /color-severity-low/)
    assert.match(src, /color-severity-medium/)
    assert.match(src, /color-severity-high/)
    assert.match(src, /color-severity-critical/)
  })
  it("shows a current-totals legend strip", () => {
    assert.match(src, /critical[\s\S]+high[\s\S]+medium[\s\S]+low/i)
  })
  it("body renders PostureTrendChart", () => {
    assert.match(src, /<PostureTrendChart/)
  })
})

describe("PostureSummaryTab — Beat 4b: Risk by team", () => {
  it("defines TeamRiskPanel", () => {
    assert.match(src, /function TeamRiskPanel\(/)
  })
  // #986 dropped the Risk-by-team "Repos" toggle — Top repositories is now the
  // one canonical repos view, rendered as its own panel alongside the team one.
  it("shows repos via the canonical TopReposPanel, not a team/repo toggle", () => {
    assert.doesNotMatch(src, /teamView/)
    assert.match(src, /<TopReposPanel/)
  })
  it("TeamRiskPanel measures critical + high from team data", () => {
    assert.match(src, /team\.counts\.critical \+ team\.counts\.high/)
  })
  it("body renders trend chart + team panel in a 2-col grid", () => {
    assert.match(src, /<PostureTrendChart/)
    assert.match(src, /<TeamRiskPanel/)
  })
})

describe("PostureSummaryTab — Beat 5: Compliance", () => {
  it("defines ComplianceSnapshot", () => {
    assert.match(src, /function ComplianceSnapshot\(/)
  })
  it("body renders ComplianceSnapshot", () => {
    assert.match(src, /<ComplianceSnapshot/)
  })
})

describe("PostureSummaryTab — Beat 6: Scope disclaimer", () => {
  // The VerdictAssurance component was inlined to a footer paragraph (#983);
  // the assurance intent survives as the scan-scope disclaimer at the foot.
  it("renders the scan-scope disclaimer at the foot of the view", () => {
    assert.match(src, /Covers scanned source code only/)
    assert.match(src, /runtime is not directly observed/)
  })
})

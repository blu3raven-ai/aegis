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
  it("defines sparkPath helper", () => {
    assert.match(src, /function sparkPath\(/)
  })
  it("defines Sparkline component", () => {
    assert.match(src, /function Sparkline\(/)
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
  it("RiskScoreHero shows the 90-day sparkline inside the score card", () => {
    assert.match(src, /Sparkline[\s\S]+90-day/i)
  })
  it("RiskScoreHero drops the summary paragraph from the old design", () => {
    assert.doesNotMatch(src, /riskScore\.summary/)
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
    assert.match(src, /SLA compliance/)
    assert.match(src, /Scan coverage/)
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

describe("PostureSummaryTab — Beat 3: Integration activity", () => {
  it("defines IntegrationActivityStrip", () => {
    assert.match(src, /function IntegrationActivityStrip\(/)
  })
  it("includes all five mock cell labels", () => {
    assert.match(src, /Slack alerts/)
    assert.match(src, /Webhook events/)
    assert.match(src, /Jira tickets/)
    assert.match(src, /Fix PRs/)
    assert.match(src, /Findings resolved/)
  })
  it("wires Findings resolved cell to remediation.totalFixed", () => {
    assert.match(src, /remediation\.totalFixed/)
  })
  it("body renders IntegrationActivityStrip", () => {
    assert.match(src, /<IntegrationActivityStrip/)
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
  it("includes Teams|Repos segmented toggle", () => {
    assert.match(src, /Teams\s*<\/button>[\s\S]+Repos\s*<\/button>/)
  })
  it("default team view uses team data", () => {
    assert.match(src, /teamView === "teams"/)
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

describe("PostureSummaryTab — Beat 6: Verdict assurance", () => {
  it("defines VerdictAssurance", () => {
    assert.match(src, /function VerdictAssurance\(/)
  })
  it("body renders VerdictAssurance", () => {
    assert.match(src, /<VerdictAssurance/)
  })
  it("includes scope disclaimer copy", () => {
    assert.match(src, /scanned source code only/i)
  })
})

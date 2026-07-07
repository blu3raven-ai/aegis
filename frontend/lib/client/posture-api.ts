/** Client for the security-posture surface (snapshot, trend, by-team). */
import { gqlFetch } from "./graphql-fetch.ts"

export interface PostureCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  unknown: number
}

export interface PostureTopRepository {
  name: string
  open: number
  critical: number
  high: number
}

export interface PostureAgeBucket {
  label: string
  count: number
}

export interface PostureRemediation {
  totalFixed: number
  avgDays: number | null
  medianDays: number | null
  fixedLast30d: number
}

export interface PostureRepositoryCoverage {
  total: number
  affected: number
  unaffected: number
  percentage: number
}

export interface PostureSeveritySlice {
  severity: string   // "critical" | "high" | "medium" | "low" | "unrated"
  count: number
  percentage: number
}

export interface PostureRiskScore {
  score: number
  rating: string   // "Low" | "Moderate" | "High" | "Severe"
  summary: string
}

export interface PostureSnapshotResponse {
  counts: PostureCounts
  severityDistribution: PostureSeveritySlice[]
  topRepositories: PostureTopRepository[]
  ageBuckets: PostureAgeBucket[]
  remediation: PostureRemediation
  repositoryCoverage: PostureRepositoryCoverage
  riskScore: PostureRiskScore
}

export interface TrendPoint {
  date: string        // "YYYY-MM-DD"
  risk_score: number  // 0-100
  critical: number
  high: number
  medium: number
  low: number
  total: number
  new_findings: number
}

export interface PostureTrendResponse {
  points: TrendPoint[]
  days: number
}

export interface TeamPostureItem {
  team_id: string
  team_name: string
  repo_count: number
  counts: PostureCounts
  risk_score: PostureRiskScore
}

export interface PostureByTeamResponse {
  teams: TeamPostureItem[]
}
interface GqlSnapshotResponse {
  posture: {
    snapshot: {
      counts: PostureCounts
      severityDistribution: PostureSeveritySlice[]
      topRepositories: PostureTopRepository[]
      ageBuckets: PostureAgeBucket[]
      remediation: {
        totalFixed: number
        avgDays: number | null
        medianDays: number | null
        fixedLast30d: number
      }
      repositoryCoverage: PostureRepositoryCoverage
      riskScore: PostureRiskScore
    }
  }
}

const SNAPSHOT_QUERY = `query PostureSnapshot {
  posture {
    snapshot {
      counts { total critical high medium low unknown }
      severityDistribution { severity count percentage }
      topRepositories { name open critical high }
      ageBuckets { label count }
      remediation { totalFixed avgDays medianDays fixedLast30d }
      repositoryCoverage { total affected unaffected percentage }
      riskScore { score rating summary }
    }
  }
}`

export async function getPostureSnapshot(): Promise<PostureSnapshotResponse> {
  const data = await gqlFetch<GqlSnapshotResponse>("PostureSnapshot", SNAPSHOT_QUERY, {})
  return data.posture.snapshot
}

interface GqlTrendResponse {
  posture: {
    trend: Array<{
      date: string
      riskScore: number
      critical: number
      high: number
      medium: number
      low: number
      total: number
      newFindings: number
    }>
  }
}

const TREND_QUERY = `query PostureTrend($days: Int!) {
  posture {
    trend(days: $days) {
      date
      riskScore
      critical
      high
      medium
      low
      total
      newFindings
    }
  }
}`

export async function getPostureTrend(days = 90): Promise<PostureTrendResponse> {
  const data = await gqlFetch<GqlTrendResponse>("PostureTrend", TREND_QUERY, { days })
  return {
    points: data.posture.trend.map((p) => ({
      date: p.date,
      risk_score: p.riskScore,
      critical: p.critical,
      high: p.high,
      medium: p.medium,
      low: p.low,
      total: p.total,
      new_findings: p.newFindings,
    })),
    days,
  }
}

interface GqlByTeamResponse {
  posture: {
    byTeam: Array<{
      teamId: string
      teamName: string
      repoCount: number
      counts: PostureCounts
      riskScore: PostureRiskScore
    }>
  }
}

const BY_TEAM_QUERY = `query PostureByTeam {
  posture {
    byTeam {
      teamId
      teamName
      repoCount
      counts { total critical high medium low unknown }
      riskScore { score rating summary }
    }
  }
}`

export async function getPostureByTeam(): Promise<PostureByTeamResponse> {
  const data = await gqlFetch<GqlByTeamResponse>("PostureByTeam", BY_TEAM_QUERY, {})
  return {
    teams: data.posture.byTeam.map((t) => ({
      team_id: t.teamId,
      team_name: t.teamName,
      repo_count: t.repoCount,
      counts: t.counts,
      risk_score: t.riskScore,
    })),
  }
}

// ── Triage surface: scanner breakdown, risk contributions, exploitability, SLA ─

export interface ScannerBreakdownItem {
  scanner: string
  critical: number
  high: number
  medium: number
  low: number
  total: number
  riskScore: number
  slaBreached: number
}

export interface RiskContributionItem {
  dimension: string
  label: string
  riskScore: number
  count: number
  percentage: number
}

export interface ExploitabilityTopFinding {
  findingId: number
  tool: string
  repo: string
  severity: string
  identityKey: string
  cve: string
  epssScore: number
  epssPercentile: number
  scoredDate: string | null
}

export interface ExploitabilitySummary {
  kevCount: number
  highEpssCount: number
  epssTop: ExploitabilityTopFinding[]
}

export interface SlaBreachByScanner {
  scanner: string
  breached: number
}

export interface SlaPostureSummary {
  totalBreached: number
  criticalBreached: number
  highBreached: number
  mediumBreached: number
  lowBreached: number
  maxBreachAgeDays: number
  byScanner: SlaBreachByScanner[]
}

interface GqlScannerBreakdownResponse {
  posture: {
    scannerBreakdown: Array<{
      scanner: string
      critical: number
      high: number
      medium: number
      low: number
      total: number
      riskScore: number
      slaBreached: number
    }>
  }
}

const SCANNER_BREAKDOWN_QUERY = `query PostureScannerBreakdown {
  posture {
    scannerBreakdown {
      scanner
      critical
      high
      medium
      low
      total
      riskScore
      slaBreached
    }
  }
}`

export async function getPostureScannerBreakdown(): Promise<ScannerBreakdownItem[]> {
  const data = await gqlFetch<GqlScannerBreakdownResponse>(
    "PostureScannerBreakdown",
    SCANNER_BREAKDOWN_QUERY,
    {},
  )
  return data.posture.scannerBreakdown
}

interface GqlRiskContributionsResponse {
  posture: {
    riskContributions: Array<{
      dimension: string
      label: string
      riskScore: number
      count: number
      percentage: number
    }>
  }
}

const RISK_CONTRIBUTIONS_QUERY = `query PostureRiskContributions($dimension: String!) {
  posture {
    riskContributions(dimension: $dimension) {
      dimension
      label
      riskScore
      count
      percentage
    }
  }
}`

export async function getPostureRiskContributions(
  dimension: string,
): Promise<RiskContributionItem[]> {
  const data = await gqlFetch<GqlRiskContributionsResponse>(
    "PostureRiskContributions",
    RISK_CONTRIBUTIONS_QUERY,
    { dimension },
  )
  return data.posture.riskContributions
}

interface GqlExploitabilitySummaryResponse {
  posture: {
    exploitabilitySummary: {
      kevCount: number
      highEpssCount: number
      epssTop: Array<{
        findingId: number
        tool: string
        repo: string
        severity: string
        identityKey: string
        cve: string
        epssScore: number
        epssPercentile: number
        scoredDate: string | null
      }>
    }
  }
}

const EXPLOITABILITY_SUMMARY_QUERY = `query PostureExploitabilitySummary {
  posture {
    exploitabilitySummary {
      kevCount
      highEpssCount
      epssTop {
        findingId
        tool
        repo
        severity
        identityKey
        cve
        epssScore
        epssPercentile
        scoredDate
      }
    }
  }
}`

export async function getPostureExploitabilitySummary(): Promise<ExploitabilitySummary> {
  const data = await gqlFetch<GqlExploitabilitySummaryResponse>(
    "PostureExploitabilitySummary",
    EXPLOITABILITY_SUMMARY_QUERY,
    {},
  )
  return data.posture.exploitabilitySummary
}

interface GqlSlaPostureResponse {
  posture: {
    slaPosture: {
      totalBreached: number
      criticalBreached: number
      highBreached: number
      mediumBreached: number
      lowBreached: number
      maxBreachAgeDays: number
      byScanner: Array<{
        scanner: string
        breached: number
      }>
    }
  }
}

const SLA_POSTURE_QUERY = `query PostureSlaPosture {
  posture {
    slaPosture {
      totalBreached
      criticalBreached
      highBreached
      mediumBreached
      lowBreached
      maxBreachAgeDays
      byScanner {
        scanner
        breached
      }
    }
  }
}`

export async function getPostureSlaPosture(): Promise<SlaPostureSummary> {
  const data = await gqlFetch<GqlSlaPostureResponse>(
    "PostureSlaPosture",
    SLA_POSTURE_QUERY,
    {},
  )
  return data.posture.slaPosture
}

/** Client for the security-posture surface (snapshot, trend, by-team). */

export interface PostureCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
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

export interface PostureRiskScore {
  score: number
  rating: string   // "Low" | "Moderate" | "High" | "Severe"
  summary: string
}

export interface PostureSnapshotResponse {
  counts: PostureCounts
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

const CSRF_COOKIE_NAME = "__Host-csrf"

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=")
    if (k === CSRF_COOKIE_NAME) return rest.join("=")
  }
  return null
}

async function gqlFetch<T>(operationName: string, query: string, variables: Record<string, unknown>): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) headers["X-CSRF-Token"] = csrf

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ operationName, query, variables }),
    credentials: "include",
  })
  const body = (await res.json()) as { data?: T; errors?: { message: string }[] }
  if (body.errors && body.errors.length > 0) {
    throw new Error(body.errors[0].message)
  }
  if (!body.data) {
    throw new Error(`${operationName} returned no data`)
  }
  return body.data
}

interface GqlSnapshotResponse {
  posture: {
    snapshot: {
      counts: PostureCounts
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
      counts { total critical high medium low }
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
      counts { total critical high medium low }
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

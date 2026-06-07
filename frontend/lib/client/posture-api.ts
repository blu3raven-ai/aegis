import { apiClient } from "./api-client.ts"

const BASE = "/api/v1/posture"

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

export async function getPostureSnapshot(orgId?: string): Promise<PostureSnapshotResponse> {
  const qs = orgId ? `?org_id=${encodeURIComponent(orgId)}` : ""
  return apiClient<PostureSnapshotResponse>(`${BASE}/snapshot${qs}`)
}

export async function getPostureTrend(orgId?: string, days = 90): Promise<PostureTrendResponse> {
  const params = new URLSearchParams({ days: String(days) })
  if (orgId) params.set("org_id", orgId)
  return apiClient<PostureTrendResponse>(`${BASE}/trend?${params}`)
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
  org: string
}

export async function getPostureByTeam(orgId?: string): Promise<PostureByTeamResponse> {
  const qs = orgId ? `?org_id=${encodeURIComponent(orgId)}` : ""
  return apiClient<PostureByTeamResponse>(`${BASE}/by-team${qs}`)
}

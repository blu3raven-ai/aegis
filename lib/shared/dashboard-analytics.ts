import type { DependenciesFinding } from "@/lib/shared/dependencies/types"

interface GitHubRepo {
  id: number
  archived?: boolean
  disabled?: boolean
}

export interface Counts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface SeverityDistributionItem {
  severity: "critical" | "high" | "medium" | "low"
  count: number
  percentage: number
}

export interface AgeBucket {
  label: string
  count: number
}

export interface TopRepository {
  name: string
  open: number
  critical: number
  high: number
}

export interface RemediationMetrics {
  totalFixed: number
  avgDays: number | null
  medianDays: number | null
  fixedLast30d: number
}

export interface RepositoryCoverage {
  total: number
  affected: number
  unaffected: number
  percentage: number
}

export interface RiskScore {
  score: number
  rating: "Low" | "Moderate" | "High" | "Severe"
  summary: string
}

export interface AnalyticsPayload {
  counts: Counts
  severityDistribution: SeverityDistributionItem[]
  ageBuckets: AgeBucket[]
  topRepositories: TopRepository[]
  remediation: RemediationMetrics
  repositoryCoverage: RepositoryCoverage
  riskScore: RiskScore
}

export function getCounts(alerts: DependenciesFinding[]): Counts {
  return {
    total: alerts.length,
    critical: alerts.filter((a) => a.security_advisory.severity === "critical").length,
    high: alerts.filter((a) => a.security_advisory.severity === "high").length,
    medium: alerts.filter((a) => a.security_advisory.severity === "medium").length,
    low: alerts.filter((a) => a.security_advisory.severity === "low").length,
  }
}

export function getSeverityDistribution(alerts: DependenciesFinding[]): SeverityDistributionItem[] {
  const counts = getCounts(alerts)
  const total = Math.max(counts.total, 1)

  return [
    { severity: "critical", count: counts.critical, percentage: Math.round((counts.critical / total) * 100) },
    { severity: "high", count: counts.high, percentage: Math.round((counts.high / total) * 100) },
    { severity: "medium", count: counts.medium, percentage: Math.round((counts.medium / total) * 100) },
    { severity: "low", count: counts.low, percentage: Math.round((counts.low / total) * 100) },
  ]
}

export function getAgeBuckets(alerts: DependenciesFinding[]): AgeBucket[] {
  const buckets: AgeBucket[] = [
    { label: "0-7d", count: 0 },
    { label: "8-30d", count: 0 },
    { label: "31-90d", count: 0 },
    { label: "90d+", count: 0 },
  ]

  const now = Date.now()
  for (const alert of alerts) {
    const ageDays = Math.floor((now - new Date(alert.created_at).getTime()) / 86_400_000)
    if (ageDays <= 7) buckets[0].count += 1
    else if (ageDays <= 30) buckets[1].count += 1
    else if (ageDays <= 90) buckets[2].count += 1
    else buckets[3].count += 1
  }

  return buckets
}

export function getTopRepositories(alerts: DependenciesFinding[]): TopRepository[] {
  const repoMap = new Map<string, TopRepository>()

  for (const alert of alerts) {
    const key = alert.repository.full_name
    const existing = repoMap.get(key) ?? { name: alert.repository.full_name, open: 0, critical: 0, high: 0 }
    existing.open += 1
    if (alert.security_advisory.severity === "critical") existing.critical += 1
    if (alert.security_advisory.severity === "high") existing.high += 1
    repoMap.set(key, existing)
  }

  return Array.from(repoMap.values())
    .sort((a, b) => {
      if (b.critical !== a.critical) return b.critical - a.critical
      if (b.high !== a.high) return b.high - a.high
      return b.open - a.open
    })
    .slice(0, 5)
}

function getMedian(values: number[]) {
  const middle = Math.floor(values.length / 2)
  if (values.length % 2 === 0) return (values[middle - 1] + values[middle]) / 2
  return values[middle]
}

export function getRemediationMetrics(alerts: DependenciesFinding[]): RemediationMetrics {
  const resolvedDurations = alerts
    .map((alert) => {
      const fixedAt = alert.fixed_at ? new Date(alert.fixed_at).getTime() : null
      const createdAt = new Date(alert.created_at).getTime()
      if (!fixedAt || Number.isNaN(createdAt)) return null
      return Math.max(0, (fixedAt - createdAt) / 86_400_000)
    })
    .filter((value): value is number => value != null)
    .sort((a, b) => a - b)

  const totalFixed = resolvedDurations.length
  const avgDays = totalFixed
    ? Math.round((resolvedDurations.reduce((sum, value) => sum + value, 0) / totalFixed) * 10) / 10
    : null
  const medianDays = totalFixed ? Math.round(getMedian(resolvedDurations) * 10) / 10 : null

  const now = Date.now()
  const fixedLast30d = alerts.filter((alert) => {
    if (!alert.fixed_at) return false
    return now - new Date(alert.fixed_at).getTime() <= 30 * 86_400_000
  }).length

  return { totalFixed, avgDays, medianDays, fixedLast30d }
}

export function getRepositoryCoverage(openAlerts: DependenciesFinding[], repos: GitHubRepo[]): RepositoryCoverage {
  const activeRepos = repos.filter((repo) => !repo.archived && !repo.disabled)
  const affectedIds = new Set(openAlerts.map((alert) => alert.repository.id))
  const affected = activeRepos.filter((repo) => affectedIds.has(repo.id)).length
  const total = activeRepos.length
  const unaffected = Math.max(total - affected, 0)
  const percentage = total ? Math.round((affected / total) * 100) : 0
  return { total, affected, unaffected, percentage }
}

export function getRiskScore(openAlerts: DependenciesFinding[]): RiskScore {
  const counts = getCounts(openAlerts)
  const total = Math.max(counts.total, 1)
  const urgentShare = (counts.critical + counts.high) / total
  const score = Math.max(0, Math.min(100, Math.round(urgentShare * 100)))

  const rating =
    score >= 75 ? "Severe"
    : score >= 55 ? "High"
    : score >= 35 ? "Moderate"
    : "Low"

  const summary =
    rating === "Severe" ? "A large share of open issues are critical or high severity."
    : rating === "High" ? "High-severity work is a significant part of the open backlog."
    : rating === "Moderate" ? "Critical/high issues are present but not dominating the backlog."
    : "Overall exposure is relatively contained right now."

  return { score, rating, summary }
}

export function buildAnalytics(openAlerts: DependenciesFinding[], fixedAlerts: DependenciesFinding[], repos: GitHubRepo[]): AnalyticsPayload {
  return {
    counts: getCounts(openAlerts),
    severityDistribution: getSeverityDistribution(openAlerts),
    ageBuckets: getAgeBuckets(openAlerts),
    topRepositories: getTopRepositories(openAlerts),
    remediation: getRemediationMetrics(fixedAlerts),
    repositoryCoverage: getRepositoryCoverage(openAlerts, repos),
    riskScore: getRiskScore(openAlerts),
  }
}

import type { DependenciesFinding } from "@/lib/shared/dependencies/types"

// ── Identity key (must match backend lifecycle.finding_identity_key) ─────────

export function findingIdentityKey(alert: DependenciesFinding): string {
  const repo = alert.repository.name
  const packageName = alert.dependency.package.name
  const ecosystem = alert.dependency.package.ecosystem
  const advisoryId = alert.security_advisory.ghsa_id
  return `${repo}::${packageName}::${ecosystem}::${advisoryId}`
}

// ── Filter state ───────────────────────────────────────────────────────────────

export interface ContainerScanningFilterState {
  state: string          // "open" | "deferred" | "fixed" | "dismissed" | ""
  severity: string[]     // multi-select
  ecosystem: string[]    // multi-select
  organization: string
  repository: string
  packageSearch: string
  ageBucket: string      // matches CONTAINER_SCANNING_AGE_BUCKETS label
}

export const DEFAULT_CONTAINER_SCANNING_FILTERS: ContainerScanningFilterState = {
  state: "open",
  severity: [],
  ecosystem: [],
  organization: "",
  repository: "",
  packageSearch: "",
  ageBucket: "",
}

export interface OpenFindingsFilterOpts {
  state?: string
  severity?: string[]
  ecosystem?: string[]
  organization?: string
  repository?: string
  packageSearch?: string
  ageBucket?: string
}

// ── Age buckets ────────────────────────────────────────────────────────────────

export const CONTAINER_SCANNING_AGE_BUCKETS = [
  { label: "< 7d",  minDays: 0,   maxDays: 7   },
  { label: "7–30d", minDays: 7,   maxDays: 30  },
  { label: "1–3mo", minDays: 30,  maxDays: 90  },
  { label: "3–6mo", minDays: 90,  maxDays: 180 },
  { label: "6mo+",  minDays: 180, maxDays: Infinity },
] as const

// ── Per-alert helpers ──────────────────────────────────────────────────────────

export function alertAgeDays(alert: DependenciesFinding, nowMs = Date.now()): number {
  if (!alert.created_at) return 0
  const ms = new Date(alert.created_at).getTime()
  if (isNaN(ms)) return 0
  return (nowMs - ms) / 86_400_000
}

export function alertOrganization(alert: DependenciesFinding): string {
  return alert.repository.full_name.split("/")[0] ?? ""
}

export function alertPatchVersion(alert: DependenciesFinding): string | null {
  return alert.security_vulnerability.first_patched_version?.identifier ?? null
}

// ── Derived collections ────────────────────────────────────────────────────────

/** Findings that are open and have been unpatched for more than `thresholdDays`. */
export function computeStaleFindings(
  findings: DependenciesFinding[],
  thresholdDays: number,
  nowMs = Date.now()
): DependenciesFinding[] {
  return findings.filter(
    (a) => a.state === "open" && alertAgeDays(a, nowMs) >= thresholdDays
  )
}

/** Findings to surface in the Findings "needs attention" queue:
 *  open AND (critical or high) AND open for > 30 days. */
export function computeNeedsAttentionQueue(
  findings: DependenciesFinding[],
  nowMs = Date.now()
): DependenciesFinding[] {
  return findings.filter((a) => {
    const sev = a.security_advisory.severity
    return (
      a.state === "open" &&
      (sev === "critical" || sev === "high") &&
      alertAgeDays(a, nowMs) > 30
    )
  })
}

export interface EcosystemCount {
  ecosystem: string
  count: number
}

/** Open findings grouped by ecosystem, sorted descending by count. */
export function computeEcosystemBreakdown(findings: DependenciesFinding[]): EcosystemCount[] {
  const open = findings.filter((a) => a.state === "open")
  const counts = new Map<string, number>()
  for (const a of open) {
    const eco = a.dependency.package.ecosystem.toLowerCase()
    counts.set(eco, (counts.get(eco) ?? 0) + 1)
  }
  return Array.from(counts.entries())
    .map(([ecosystem, count]) => ({ ecosystem, count }))
    .sort((a, b) => b.count - a.count)
}

export interface VulnerablePackage {
  name: string
  ecosystem: string
  repoCount: number
  severityCounts: { critical: number; high: number; medium: number; low: number }
}

/** Packages appearing across the most repos (open findings only). */
export function computeTopVulnerablePackages(
  findings: DependenciesFinding[],
  limit = 10
): VulnerablePackage[] {
  const open = findings.filter((a) => a.state === "open")
  const pkgMap = new Map<string, VulnerablePackage>()

  for (const a of open) {
    const key = `${a.dependency.package.ecosystem}::${a.dependency.package.name}`
    const existing = pkgMap.get(key) ?? {
      name: a.dependency.package.name,
      ecosystem: a.dependency.package.ecosystem,
      repoCount: 0,
      severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
    }
    existing.repoCount += 1
    const sev = a.security_advisory.severity
    existing.severityCounts[sev as keyof typeof existing.severityCounts] += 1
    pkgMap.set(key, existing)
  }

  return Array.from(pkgMap.values())
    .sort((a, b) => b.repoCount - a.repoCount)
    .slice(0, limit)
}

export interface MTTRBySeverity {
  critical: number | null
  high: number | null
  medium: number | null
  low: number | null
}

/** Mean time to remediate per severity (days), computed from fixed findings. */
export function computeMTTRBySeverity(findings: DependenciesFinding[]): MTTRBySeverity {
  function avg(sev: "critical" | "high" | "medium" | "low"): number | null {
    const durations = findings
      .filter((a) => a.fixed_at && a.security_advisory.severity === sev)
      .map((a) => (new Date(a.fixed_at!).getTime() - new Date(a.created_at).getTime()) / 86_400_000)
      .filter((d) => d >= 0)
    if (!durations.length) return null
    return Math.round((durations.reduce((s, v) => s + v, 0) / durations.length) * 10) / 10
  }
  return {
    critical: avg("critical"),
    high: avg("high"),
    medium: avg("medium"),
    low: avg("low"),
  }
}

export interface SLAComplianceRow {
  severity: "critical" | "high" | "medium"
  thresholdDays: number
  compliant: number
  total: number
  pct: number
}

const SLA_THRESHOLDS = { critical: 7, high: 30, medium: 90 } as const

/** % of fixed findings closed within SLA per severity. */
export function computeSLACompliance(findings: DependenciesFinding[]): SLAComplianceRow[] {
  return (["critical", "high", "medium"] as const).map((sev) => {
    const threshold = SLA_THRESHOLDS[sev]
    const fixed = findings.filter((a) => a.fixed_at && a.security_advisory.severity === sev)
    const compliant = fixed.filter((a) => {
      const days = (new Date(a.fixed_at!).getTime() - new Date(a.created_at).getTime()) / 86_400_000
      return days <= threshold
    }).length
    const total = fixed.length
    const pct = total ? Math.round((compliant / total) * 100) : 0
    return { severity: sev, thresholdDays: threshold, compliant, total, pct }
  })
}

export interface MonthlyTrend {
  month: string  // "2025-01"
  introduced: number
  resolved: number
  openAtEnd: number
}

/** Month-by-month introduced / resolved / running open count. */
export function computeMonthlyTrend(findings: DependenciesFinding[]): MonthlyTrend[] {
  if (!findings.length) return []

  // Find range
  const dates = findings.map((a) => new Date(a.created_at))
  const minDate = new Date(Math.min(...dates.map((d) => d.getTime())))
  const maxDate = new Date()

  // Build month list
  const months: string[] = []
  const cursor = new Date(minDate.getFullYear(), minDate.getMonth(), 1)
  while (cursor <= maxDate) {
    months.push(`${cursor.getFullYear()}-${String(cursor.getMonth() + 1).padStart(2, "0")}`)
    cursor.setMonth(cursor.getMonth() + 1)
  }

  return months.map((month) => {
    const [y, m] = month.split("-").map(Number)
    const start = new Date(y, m - 1, 1).getTime()
    const end = new Date(y, m, 1).getTime()

    const introduced = findings.filter((a) => {
      const t = new Date(a.created_at).getTime()
      return t >= start && t < end
    }).length

    const resolved = findings.filter((a) => {
      if (!a.fixed_at) return false
      const t = new Date(a.fixed_at).getTime()
      return t >= start && t < end
    }).length

    const openAtEnd = findings.filter((a) => {
      const created = new Date(a.created_at).getTime()
      if (created >= end) return false
      if (a.state !== "open") {
        const closedAt = a.fixed_at ?? a.dismissed_at
        if (closedAt && new Date(closedAt).getTime() < end) return false
      }
      return true
    }).length

    return { month, introduced, resolved, openAtEnd }
  })
}

export interface RemediationPriorityRow {
  rank: number
  packageName: string
  ecosystem: string
  ghsaId: string
  cveId: string | null
  severity: "critical" | "high" | "medium" | "low"
  reposAffected: number
  patchVersion: string | null
  advisoryUrl: string
}

/** Unique package+advisory combinations ranked by severity then repos affected. */
export function computeRemediationPriority(findings: DependenciesFinding[]): RemediationPriorityRow[] {
  const open = findings.filter((a) => a.state === "open")
  const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

  const map = new Map<string, RemediationPriorityRow & { _repos: Set<string> }>()
  for (const a of open) {
    const key = `${a.dependency.package.name}::${a.security_advisory.ghsa_id}`
    const existing = map.get(key)
    if (existing) {
      existing._repos.add(a.repository.full_name)
      existing.reposAffected = existing._repos.size
    } else {
      map.set(key, {
        rank: 0,
        packageName: a.dependency.package.name,
        ecosystem: a.dependency.package.ecosystem,
        ghsaId: a.security_advisory.ghsa_id,
        cveId: a.security_advisory.cve_id,
        severity: a.security_advisory.severity as "critical" | "high" | "medium" | "low",
        reposAffected: 1,
        patchVersion: alertPatchVersion(a),
        advisoryUrl: a.html_url,
        _repos: new Set([a.repository.full_name]),
      })
    }
  }

  return Array.from(map.values())
    .sort((a, b) => {
      if (SEV_ORDER[a.severity] !== SEV_ORDER[b.severity])
        return SEV_ORDER[a.severity] - SEV_ORDER[b.severity]
      return b.reposAffected - a.reposAffected
    })
    .map(({ _repos, ...rest }, i) => ({ ...rest, rank: i + 1 }))
}

// ── Filter application ─────────────────────────────────────────────────────────

/** Apply ContainerScanningFilterState to a flat findings array. Does not dedupe. */
export function filterFindings(
  findings: DependenciesFinding[],
  filters: ContainerScanningFilterState,
  nowMs = Date.now()
): DependenciesFinding[] {
  return findings.filter((a) => {
    if (filters.state && a.state !== filters.state) return false
    if (filters.severity.length && !filters.severity.includes(a.security_advisory.severity)) return false
    if (
      filters.ecosystem.length &&
      !filters.ecosystem.map((e) => e.toLowerCase()).includes(a.dependency.package.ecosystem.toLowerCase())
    )
      return false
    if (
      filters.organization &&
      !alertOrganization(a).toLowerCase().includes(filters.organization.toLowerCase())
    )
      return false
    if (
      filters.repository &&
      !a.repository.name.toLowerCase().includes(filters.repository.toLowerCase())
    )
      return false
    if (
      filters.packageSearch &&
      !a.dependency.package.name.toLowerCase().includes(filters.packageSearch.toLowerCase())
    )
      return false
    if (filters.ageBucket) {
      const bucket = CONTAINER_SCANNING_AGE_BUCKETS.find((b) => b.label === filters.ageBucket)
      if (bucket) {
        const age = alertAgeDays(a, nowMs)
        if (age < bucket.minDays || age >= bucket.maxDays) return false
      }
    }
    return true
  })
}

// ── Simple filter (used by FindingsTab search bar) ─────────────────────────

export function filterFindingsSimple(
  findings: DependenciesFinding[],
  opts: {
    search: string
    state: string
    severity: string[]
    ecosystem?: string[]
    packageSearch?: string
    repository?: string
    organization?: string
    source?: string
    fixAvailability?: string
    ageBucket?: string
  }
): DependenciesFinding[] {
  const q = opts.search.toLowerCase().trim()
  const pkgQ = opts.packageSearch?.toLowerCase().trim() ?? ""
  const ageBucket = opts.ageBucket
    ? CONTAINER_SCANNING_AGE_BUCKETS.find((b) => b.label === opts.ageBucket) ?? null
    : null
  const nowMs = Date.now()

  return findings.filter((a) => {
    if (opts.state && a.state !== opts.state) return false
    if (opts.severity.length && !opts.severity.includes(a.security_advisory.severity)) return false
    if (opts.ecosystem?.length && !opts.ecosystem.includes(a.dependency.package.ecosystem)) return false
    if (opts.repository && a.repository.full_name !== opts.repository && a.repository.name !== opts.repository) return false
    if (opts.organization && alertOrganization(a) !== opts.organization) return false
    if (opts.source && (a.source ?? "git") !== opts.source) return false
    if (opts.fixAvailability === "has_fix" && !alertPatchVersion(a)) return false
    if (opts.fixAvailability === "no_fix" && alertPatchVersion(a)) return false
    if (pkgQ && !a.dependency.package.name.toLowerCase().includes(pkgQ)) return false
    if (ageBucket) {
      const days = alertAgeDays(a, nowMs)
      if (days < ageBucket.minDays || days >= ageBucket.maxDays) return false
    }
    if (q) {
      const hit =
        a.dependency.package.name.toLowerCase().includes(q) ||
        a.repository.name.toLowerCase().includes(q) ||
        (a.security_advisory.cve_id?.toLowerCase().includes(q) ?? false) ||
        a.security_advisory.ghsa_id.toLowerCase().includes(q)
      if (!hit) return false
    }
    return true
  })
}

// ── CVSS chip CSS classes ──────────────────────────────────────────────────

export function formatCvssScore(score: number | null | undefined): string {
  if (score == null || !Number.isFinite(score) || score <= 0) return "-"
  return score.toFixed(1)
}

export function cvssChipClass(score: number | null | undefined): string {
  if (score == null || !Number.isFinite(score) || score <= 0) {
    return "border border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  }
  if (score >= 9.0) return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300"
  if (score >= 7.0) return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300"
  if (score >= 4.0) return "bg-amber-100 text-amber-700 dark:bg-amber-900/20 dark:text-amber-200"
  return "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300"
}

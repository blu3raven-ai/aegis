export interface GqlSeverityCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface GqlScannerCounts {
  scans: {
    dependenciesScanning: { counts: GqlSeverityCounts }
    codeScanning: { counts: GqlSeverityCounts }
    containerScanning: { counts: GqlSeverityCounts }
    secretScanning: { counts: GqlSeverityCounts }
    iacScanning: { counts: GqlSeverityCounts }
  }
}

export interface GqlHomeRepoSummary {
  name: string
  open: number
  critical: number
  high: number
}

export interface GqlHomeAgeBucket {
  label: string
  count: number
}

export interface GqlHomeRemediationStats {
  totalFixed: number
  avgDays: number | null
  medianDays: number | null
  fixedLast30d: number
}

export interface GqlHomeAnalytics {
  topRepositories: GqlHomeRepoSummary[]
  ageBuckets: GqlHomeAgeBucket[]
  remediation: GqlHomeRemediationStats
}

export interface GqlPostureTrendPoint {
  date: string
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface GqlEpssTopFinding {
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

export interface GqlEpssTopResponse {
  findings: GqlEpssTopFinding[]
  count: number
}

export interface GqlHomeDashboard {
  scans: {
    dependenciesScanning: { counts: GqlSeverityCounts }
    codeScanning: { counts: GqlSeverityCounts }
    containerScanning: { counts: GqlSeverityCounts }
    secretScanning: { counts: GqlSeverityCounts }
    iacScanning: { counts: GqlSeverityCounts }
  }
  posture: {
    trend: GqlPostureTrendPoint[]
    homeAnalytics: GqlHomeAnalytics
  }
  sla: {
    epssTop: GqlEpssTopResponse
  }
}

export type SecretReviewStatus = "new" | "confirmed" | "false_positive" | "action_taken"

export type SecretSortOrder = "newest" | "oldest" | "occurrences" | "risk"

export type SecretRunStatus = "queued" | "running" | "ingesting" | "completed" | "failed" | "cancelled"

export interface SecretFinding {
  id: string
  runId: string
  organization: string
  repository: string
  source: string
  detector: string
  classificationHistory: ClassificationEntry[]
  secretSnippet: string
  filePath: string | null
  line: number | null
  commit: string | null
  detectedAt: string | null
  fingerprint: string
  secretIdentity?: string | null
  reviewStatus: SecretReviewStatus
  occurrenceCount?: number
  repoHistorySignal?: {
    confirmedCount: number
  }
  detectorNoiseRate?: number
  secretAgeDays?: number | null
  riskScore?: number
  raw: Record<string, unknown>
  confirmedAt?: string | null
  resolvedAt?: string | null
}

export interface SecretScanRun {
  id: string
  organization: string
  status: SecretRunStatus
  createdAt: string
  startedAt: string | null
  finishedAt: string | null
  lastHeartbeatAt?: string | null
  lastProgressAt?: string | null
  lastStatusTransitionAt?: string | null
  reconciled?: boolean
  reconciliationReason?: string | null
  scanDepth?: string
  findingsCount: number
  error: string | null
  logTail: string[]
  progress: {
    expectedRepos: number | null
    scannedRepos: number
    finishedRepos: number
    percent: number
    currentRepo: string | null
    currentClassifying: string | null
    stage: "queued" | "scanning" | "classifying" | "ingesting" | "completed" | "failed" | "cancelled"
  }
}

export interface SecretDecision {
  status: SecretReviewStatus
  updatedAt: string
  fingerprint?: string
  repository?: string | null
  source?: string | null
  detector?: string | null
  filePath?: string | null
  line?: number | null
  commit?: string | null
  secretIdentity?: string | null
  scope?: "occurrence" | "secret"
}

export interface SecretsSnapshot {
  meta: {
    organization: string
    lastUpdatedAt: string
    lastRunId: string | null
  }
  stats: {
    total: number
    repositoriesAffected: number
    sources: number
    newCount: number
    confirmedCount: number
    falsePositiveCount: number
    actionTakenCount?: number
  }
  sourceBreakdown: Array<{ source: string; count: number }>
  findings: SecretFinding[]
  remediation?: {
    medianDays: number | null
    avgDays: number | null
    fixedLast30d: number
    totalFixed: number
  }
  repositoryCoverage?: {
    percentage: number
    affected: number
    unaffected: number
  }
}

export interface SecretsReviewQueueResponse {
  empty: boolean
  queue: SecretFinding[]
  error?: string
}

export interface SecretsInsightsRepoPriority {
  organization: string
  repository: string
  unreviewedCount: number
  confirmedCount: number
  repeatOffender: boolean
  lastSeenDate: string | null
  urgencyScore: number
}

export interface SecretsTrendEndOfMonth {
  unresolved: number
  resolved: number
  falsePositive: number
  confirmed: number
}

export interface SecretsTrendEntry {
  month: string
  newlyDetected: number
  resolved: number
  triaged: number
  falsePositive: number
  endOfMonth: SecretsTrendEndOfMonth
}

export interface SecretsInsightsResponse {
  triagePriority: SecretsInsightsRepoPriority[]
  trend: SecretsTrendEntry[]
  error?: string
}

export interface SecretsHealthRunEntry extends SecretScanRun {
  durationSeconds?: number | null
  distinctFindingsCount?: number | null
}

export interface SecretsCoverageGap {
  repository: string
  reason: "stale" | "missing_checkpoint"
  lastScannedAt: string | null
}

export interface SecretsScannerHitRate {
  runId: string | null
  organization: string | null
  createdAt: string | null
  trufflehogCount: number
  trufflehogStatus: "green" | "amber" | "red"
}

export interface SecretsHealthResponse {
  empty: boolean
  runHistory: SecretsHealthRunEntry[]
  coverageGaps: SecretsCoverageGap[]
  scannerHitRates: SecretsScannerHitRate[]
  error?: string
}

export type SecretClassification = "confirmed" | "likely_real" | "uncertain" | "false_positive"

export interface ClassificationEntry {
  value: SecretClassification
  source: "scanner" | "ai"
  scanDepth: "light" | "deep" | null
  confidence: number
  runId: string
  scannedAt: string
}

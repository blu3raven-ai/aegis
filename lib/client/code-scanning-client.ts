import { CODE_SCANNING_API } from "@/lib/shared/api-paths"
import { readJsonResponse } from "@/lib/shared/client-json"

export interface CodeScanningScanRun {
  id: string
  org: string
  status: "queued" | "running" | "ingesting" | "ai_review" | "completed" | "failed" | "cancelled"
  scanMode?: string
  createdAt?: string
  startedAt?: string
  finishedAt?: string
  findingsCount?: number
  durationSeconds?: number
  error?: string
  logTail?: string[]
  progress?: {
    expectedRepos?: number | null
    scannedRepos?: number
    finishedRepos?: number
    percent?: number
    currentRepo?: string | null
    stage?: string
  }
}

export interface CodeScanningRunsResponse {
  latest?: CodeScanningScanRun
  lastCompleted?: CodeScanningScanRun
  error?: string
}

export interface CodeScanningHistoryResponse {
  history: CodeScanningScanRun[]
  coverageGaps: Array<{ repository: string; reason: string; lastScannedAt: string | null }>
}

export interface CodeScanningStartRunsResponse {
  runs?: Array<{ org: string; runId: string }>
  message?: string
  error?: string
}

export interface CodeScanningFinding {
  identity_key: string
  repo_full_name: string
  repo_html_url?: string
  file_path: string
  start_line: number
  end_line: number
  rule_id: string
  rule_name: string
  severity: "critical" | "high" | "medium" | "low"
  confidence: string
  category: string
  cwe: string[]
  message: string
  snippet: string
  fix_suggestion?: string
  state: "open" | "dismissed" | "fixed" | "awaiting_fix"
  first_seen_at?: string
  fixed_at?: string
  dismissed_at?: string
  dismissed_by?: string
  dismissed_reason?: string
  ai_review?: { verdict: string; explanation: string; reasoning?: string; confidence?: string }
  language?: string
  file_class?: string
  code_window?: string
  code_flows?: Array<{ file: string; line: number; snippet: string }>
  reachability?: {
    verdict: "reachable" | "unreachable" | "unknown"
    entry_point?: string
    call_chain?: Array<{
      function: string
      file: string
      line: number
      snippet?: string | null
    }>
  }
  // Commit attribution (PR #35)
  introduced_by_commit_sha?: string | null
  introduced_by_author?: string | null
  introduced_at?: string | null
  introduced_by_pr_url?: string | null
}

export interface CodeScanningAnalytics {
  counts: { total: number; critical: number; high: number; medium: number; low: number }
  severityDistribution: Array<{ severity: string; count: number; percentage: number }>
  topRules: Array<{ ruleId: string; count: number }>
  topRepositories: Array<{ name: string; open: number; critical: number; high: number }>
  ageBuckets?: Array<{ label: string; count: number }>
  remediation?: {
    totalFixed: number
    avgDays: number | null
    medianDays: number | null
    fixedLast30d: number
  }
  repositoryCoverage?: {
    total: number
    affected: number
    unaffected: number
    percentage: number
  }
}

async function fetchJson<T>(input: string, init?: RequestInit): Promise<{ ok: boolean; payload: T }> {
  const response = await fetch(input, init)
  const payload = await readJsonResponse<T>(response)
  return { ok: response.ok, payload }
}

export function fetchCodeScanningRuns(orgQuery: string) {
  return fetchJson<CodeScanningRunsResponse>(`${CODE_SCANNING_API.runsLatest}?${orgQuery}`)
}

export function fetchCodeScanningHistory(orgQuery: string) {
  return fetchJson<CodeScanningHistoryResponse>(`${CODE_SCANNING_API.history}?${orgQuery}`)
}

export function startCodeScanningRuns(
  orgQuery: string,
  scanMode?: "full" | "rules_only" | "ai_review_only",
) {
  const params = new URLSearchParams(orgQuery)
  if (scanMode) params.set("scan_mode", scanMode)
  return fetchJson<CodeScanningStartRunsResponse>(
    `${CODE_SCANNING_API.runs}?${params.toString()}`,
    { method: "POST" },
  )
}

export function cancelCodeScanningRuns(orgQuery: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(`${CODE_SCANNING_API.runsCancel}?${orgQuery}`, { method: "POST" })
}

export function dismissCodeScanningFinding(org: string, identityKey: string, reason: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(CODE_SCANNING_API.findingsDismiss, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKey, reason }),
  })
}

export function reopenCodeScanningFinding(org: string, identityKey: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(CODE_SCANNING_API.findingsReopen, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKey }),
  })
}

export function bulkReviewCodeScanningFindings(
  org: string,
  identityKeys: string[],
  action: "dismiss" | "reopen",
  reason?: string,
) {
  return fetchJson<{ ok?: boolean; updated?: number; error?: string }>(CODE_SCANNING_API.findingsReview, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKeys, action, reason }),
  })
}

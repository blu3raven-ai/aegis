import { DEPENDENCIES_API } from "@/lib/shared/api-paths"
import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

export interface DependenciesScanRun {
  id: string
  org: string
  status: "queued" | "running" | "ingesting" | "completed" | "failed" | "cancelled"
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

export interface DependenciesRunsResponse {
  latest?: DependenciesScanRun
  lastCompleted?: DependenciesScanRun
  hasSboms?: boolean
  error?: string
}

export interface DependenciesStartRunsResponse {
  runs?: Array<{ org: string; runId: string }>
  message?: string
  error?: string
}

async function fetchJson<T>(url: string, options?: { method?: string; body?: unknown }): Promise<{ ok: boolean; payload: T }> {
  try {
    const payload = await apiClient<T>(url, options)
    return { ok: true, payload }
  } catch (err) {
    if (err instanceof ApiClientError) {
      return { ok: false, payload: (err.body ?? {}) as T }
    }
    return { ok: false, payload: {} as T }
  }
}

export function fetchDependenciesRuns(orgQuery: string) {
  return fetchJson<DependenciesRunsResponse>(`${DEPENDENCIES_API.runsLatest}?${orgQuery}`)
}

export function startDependenciesRuns(
  orgQuery: string,
  mode?: "full" | "incremental",
  scanMode?: "full" | "sbom_only" | "advisories_only",
) {
  const params = new URLSearchParams(orgQuery)
  if (mode) params.set("mode", mode)
  if (scanMode) params.set("scan_mode", scanMode)
  return fetchJson<DependenciesStartRunsResponse>(`${DEPENDENCIES_API.runs}?${params.toString()}`, { method: "POST" })
}

export function cancelDependenciesRuns(orgQuery: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(`${DEPENDENCIES_API.runsCancel}?${orgQuery}`, { method: "POST" })
}

export function dismissDependenciesFinding(org: string, identityKey: string, reason: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(DEPENDENCIES_API.findingsDismiss, {
    method: "POST",
    body: { org, identityKey, reason },
  })
}

export function reopenDependenciesFinding(org: string, identityKey: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(DEPENDENCIES_API.findingsReopen, {
    method: "POST",
    body: { org, identityKey },
  })
}

export function bulkReviewDependenciesFindings(
  org: string,
  identityKeys: string[],
  action: "dismiss" | "reopen",
  reason?: string,
) {
  return fetchJson<{ ok?: boolean; updated?: number; error?: string }>(DEPENDENCIES_API.findingsReview, {
    method: "PATCH",
    body: { org, identityKeys, action, reason },
  })
}


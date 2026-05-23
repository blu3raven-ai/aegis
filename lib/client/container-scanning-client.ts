import { CONTAINER_SCANNING_API } from "@/lib/shared/api-paths"
import { readJsonResponse } from "@/lib/shared/client-json"

export interface ContainerScanningRun {
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

export interface ContainerScanningRunsResponse {
  latest?: ContainerScanningRun
  lastCompleted?: ContainerScanningRun
  hasSboms?: boolean
  error?: string
}

export interface ContainerScanningStartRunsResponse {
  runs?: Array<{ org: string; runId: string }>
  message?: string
  error?: string
}

async function fetchJson<T>(input: string, init?: RequestInit): Promise<{ ok: boolean; payload: T }> {
  const response = await fetch(input, init)
  const payload = await readJsonResponse<T>(response)
  return { ok: response.ok, payload }
}

export function fetchContainerScanningRuns(orgQuery: string) {
  return fetchJson<ContainerScanningRunsResponse>(`${CONTAINER_SCANNING_API.runsLatest}?${orgQuery}`)
}

export function startContainerScanningRuns(orgQuery: string, mode?: "full" | "incremental", scanMode: string = "full") {
  const params = new URLSearchParams(orgQuery)
  if (mode) params.set("mode", mode)
  if (scanMode !== "full") params.set("scan_mode", scanMode)
  const url = `${CONTAINER_SCANNING_API.runs}?${params.toString()}`
  return fetchJson<ContainerScanningStartRunsResponse>(url, { method: "POST" })
}

export function cancelContainerScanningRuns(orgQuery: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(`${CONTAINER_SCANNING_API.runsCancel}?${orgQuery}`, { method: "POST" })
}

export function dismissContainerScanningFinding(org: string, identityKey: string, reason: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(CONTAINER_SCANNING_API.findingsDismiss, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKey, reason }),
  })
}

export function reopenContainerScanningFinding(org: string, identityKey: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(CONTAINER_SCANNING_API.findingsReopen, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKey }),
  })
}

export function bulkReviewContainerScanningFindings(
  org: string,
  identityKeys: string[],
  action: "dismiss" | "reopen",
  reason?: string,
) {
  return fetchJson<{ ok?: boolean; updated?: number; error?: string }>(CONTAINER_SCANNING_API.findingsReview, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKeys, action, reason }),
  })
}

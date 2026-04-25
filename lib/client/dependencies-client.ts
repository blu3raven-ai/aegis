import { DEPENDENCIES_API } from "@/lib/shared/api-paths"
import { readJsonResponse } from "@/lib/shared/client-json"

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
  error?: string
}

export interface DependenciesStartRunsResponse {
  runs?: Array<{ org: string; runId: string }>
  message?: string
  error?: string
}

async function fetchJson<T>(input: string, init?: RequestInit): Promise<{ ok: boolean; payload: T }> {
  const response = await fetch(input, init)
  const payload = await readJsonResponse<T>(response)
  return { ok: response.ok, payload }
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
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKey, reason }),
  })
}

export function reopenDependenciesFinding(org: string, identityKey: string) {
  return fetchJson<{ ok?: boolean; error?: string }>(DEPENDENCIES_API.findingsReopen, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKey }),
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
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, identityKeys, action, reason }),
  })
}

export interface ManifestPreviewResponse {
  filePath: string
  lines: Array<{ number: number; content: string; highlighted: boolean }>
  repositoryUrl: string
  error?: string
}

export async function fetchManifestPreview(
  repo: string,
  path: string,
  pkg: string
): Promise<ManifestPreviewResponse> {
  const params = new URLSearchParams({ repo, path, pkg })
  try {
    const res = await fetch(`/api/dependencies/manifest-preview?${params.toString()}`, {
      cache: "no-store",
    })
    if (!res.ok) {
      return {
        filePath: path,
        lines: [],
        repositoryUrl: "",
        error: `Request failed (${res.status})`,
      }
    }
    return (await res.json()) as ManifestPreviewResponse
  } catch {
    return {
      filePath: path,
      lines: [],
      repositoryUrl: "",
      error: "Network error fetching manifest",
    }
  }
}

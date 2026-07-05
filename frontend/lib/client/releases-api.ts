/** Client for the releases surface (list and per-scan detail). */

import { apiClient } from "./api-client"
import { ApiClientError } from "./api-client.types"

export interface ReleaseTriggeredBy {
  actor_type: "user" | "ci"
  actor_id: string
  display_name: string
}

export interface ReleaseSummary {
  scan_id: string
  repo_id: string
  repo: string
  ref: string | null
  commit_sha: string
  short_sha: string
  verdict: "go" | "warn" | "no_go" | "pending" | "unknown"
  blocker_count: number
  warn_count: number
  scanner_count: number
  status: "queued" | "running" | "completed" | "failed"
  started_at: string | null
  finished_at: string | null
  triggered_by: ReleaseTriggeredBy
}

export interface BlockerDiffRow {
  finding_id: number
  diff_status: "new" | "persisted" | "gone" | "fixed"
  severity: string
  title: string
  file_path: string | null
  cve_id: string | null
  cwe_id: string | null
  scanner: string
  first_seen_at: string
  introduced_by_commit_sha: string | null
  is_kev: boolean
  epss_score: number | null
}

export interface ReleaseDetail extends ReleaseSummary {
  baseline_scan_id: string | null
  baseline_ref: string | null
  baseline_taken_at: string | null
  scanners_run: string[]
  blockers_diff: BlockerDiffRow[]
  improvements: BlockerDiffRow[]
}

export interface ReleasesListResponse {
  releases: ReleaseSummary[]
  next_cursor: string | null
}

export interface ListReleasesFilters {
  repo_id?: string
  status?: string
  verdict?: string
  limit?: number
  cursor?: string
}

function buildQuery(filters: ListReleasesFilters): string {
  const qs = new URLSearchParams()
  if (filters.repo_id) qs.set("repo_id", filters.repo_id)
  if (filters.status) qs.set("status", filters.status)
  if (filters.verdict) qs.set("verdict", filters.verdict)
  if (typeof filters.limit === "number") qs.set("limit", String(filters.limit))
  if (filters.cursor) qs.set("cursor", filters.cursor)
  return qs.toString()
}

export async function listReleases(
  filters: ListReleasesFilters = {},
): Promise<ReleasesListResponse> {
  const qs = buildQuery(filters)
  const path = qs ? `/api/v1/history/releases?${qs}` : "/api/v1/history/releases"
  return apiClient<ReleasesListResponse>(path)
}

export async function getRelease(scanId: string): Promise<ReleaseDetail | null> {
  try {
    return await apiClient<ReleaseDetail>(`/api/v1/history/releases/${encodeURIComponent(scanId)}`)
  } catch (err) {
    if (err instanceof ApiClientError && err.status === 404) return null
    throw err
  }
}

/**
 * TypeScript client for the repos asset management REST API (Phase 27).
 *
 * All endpoints proxy through Next.js to the FastAPI backend at /api/v1/repos.
 */

import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

export interface RepoSummary {
  repo_id: string
  org: string
  repo: string
  last_scanned_sha?: string | null
  manifest_set_hash?: string | null
  last_scanned_at?: string | null
  findings_count_by_severity: { critical: number; high: number; medium: number; low: number }
  /** Which scanner types have a completed run: 'dependencies' | 'code_scanning' | 'container_scanning' | 'secrets' */
  scanners_with_coverage: string[]
  /** Derived from last_scanned_at: fresh = within 7d, stale = older, never = no scan. */
  coverage_status: "fresh" | "stale" | "never"
  source_url?: string | null
}

export interface ScanRunRow {
  scan_id: string
  scanner_type: string
  status: string
  started_at: string
  duration_ms?: number | null
  findings_count: number
}

export interface FindingRow {
  id: number
  tool: string
  severity?: string | null
  state: string
  identity_key: string
  repo?: string | null
  first_seen_at: string
  last_seen_at: string
}

export interface RepoDetail extends RepoSummary {
  scan_history: ScanRunRow[]
  active_findings: FindingRow[]
  default_branch?: string | null
}

export async function listRepos(filters: {
  org_id?: string
  since_days?: number
  has_critical?: boolean
  limit?: number
} = {}): Promise<RepoSummary[]> {
  const params = new URLSearchParams()
  if (filters.org_id) params.set("org_id", filters.org_id)
  if (filters.since_days != null) params.set("since_days", String(filters.since_days))
  if (filters.has_critical != null) params.set("has_critical", String(filters.has_critical))
  if (filters.limit != null) params.set("limit", String(filters.limit))
  const qs = params.toString()
  const data = await apiClient<{ repos: RepoSummary[] }>(`/api/v1/repos${qs ? `?${qs}` : ""}`)
  return data.repos ?? []
}

export async function getRepo(repoId: string): Promise<RepoDetail | null> {
  try {
    return await apiClient<RepoDetail>(`/api/v1/repos/${encodeURIComponent(repoId)}`)
  } catch (err: unknown) {
    if (err instanceof ApiClientError && err.status === 404) return null
    throw err
  }
}

// ── Scan submission ────────────────────────────────────────────────────────────

export interface ScanSubmission {
  scan_id: string
  repo_id: string
  commit_sha: string
  scanner_types: string[]
  status: string
  submitted_at: string
  submitted_by: string
}

export interface ScanFindingCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface ScanDetail {
  scan_id: string
  repo_id: string
  commit_sha: string
  scanner_types: string[]
  status: "queued" | "running" | "completed" | "failed"
  submitted_at: string
  submitted_by: string
  started_at: string | null
  finished_at: string | null
  finding_counts: ScanFindingCounts | null
  error: string | null
}

// Omitting scanner_types triggers a full scan on the backend; pass an array to restrict.
export async function submitScan(
  repoId: string,
  commitSha: string,
  scannerTypes?: string[],
): Promise<ScanSubmission> {
  const body: Record<string, unknown> = { commit_sha: commitSha }
  if (scannerTypes && scannerTypes.length > 0) body.scanner_types = scannerTypes
  return apiClient<ScanSubmission>(`/api/v1/repos/${encodeURIComponent(repoId)}/scan`, {
    method: "POST",
    body,
  })
}

export async function getScanStatus(scanId: string, orgId?: string): Promise<ScanDetail> {
  const qs = orgId ? `?org_id=${encodeURIComponent(orgId)}` : ""
  return apiClient<ScanDetail>(`/api/v1/scans/${encodeURIComponent(scanId)}${qs}`)
}

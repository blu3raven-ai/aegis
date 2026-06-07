/**
 * TypeScript client for the aggregated findings REST API (Phase 55).
 *
 * Mirrors the fetch pattern used by other clients in lib/client/. Server
 * fields stay snake_case in the wire format; we expose a camelCase
 * `epssPercentile` mirror on each row so the EPSS column rendered by
 * EpssScoreCell (Phase 54) keeps working unchanged when the backend
 * starts populating it.
 */

import { apiClient } from "./api-client.ts"

export type FindingSeverity = "critical" | "high" | "medium" | "low"
export type FindingScanner = "deps" | "container" | "sast" | "secrets" | "iac"
export type FindingState = "open" | "closed" | "dismissed" | "fixed"
export type FindingSort =
  | "severity"
  | "created_at"
  | "updated_at"
  | "severity_age"
  | "epss"
  | "risk_score"
  | "newest"
  | "oldest"
export type FindingSortDirection = "asc" | "desc"

export interface Finding {
  id: string
  scanner: FindingScanner | string
  severity: FindingSeverity | string | null
  state: string | null
  title: string | null
  cve: string | null
  package: string | null
  file_path: string | null
  line: number | null
  repo: string | null
  org_id: string
  created_at: string | null
  updated_at: string | null
  /** EPSS percentile in [0.0, 1.0]. Mirrors `epss_percentile` from the server. */
  epssPercentile?: number | null
  /** True when this finding's CVE is in CISA KEV. */
  kev?: boolean | null
  /** First CWE id (e.g. "CWE-502") from KEV metadata. */
  cwe?: string | null
  /** Server-supplied risk score 0-100. Null when no scoring path has populated it. */
  risk_score?: number | null
  /** Assigned reviewer's user id, or null when unassigned. */
  assignee_user_id?: string | null
}

export interface ListFindingsParams {
  orgId: string
  severity?: FindingSeverity[]
  scanner?: FindingScanner[]
  state?: FindingState[]
  q?: string
  cve?: string
  repo?: string
  sort?: FindingSort
  direction?: FindingSortDirection
  limit?: number
  page?: number
  /** ISO8601 timestamp — only findings first seen at or after this point. */
  first_seen_after?: string
  cwe?: string
  kev?: boolean
  epss_min?: number
  risk_score_min?: number
  assignee?: string
}

export interface FindingsListResponse {
  findings: Finding[]
  next_cursor: string | null
  total_count: number
}

interface RawFinding extends Omit<Finding, "epssPercentile"> {
  epss_percentile?: number | null
}

interface RawFindingsListResponse {
  findings: RawFinding[]
  next_cursor: string | null
  total_count: number
}

function normalizeFinding(raw: RawFinding): Finding {
  const { epss_percentile, ...rest } = raw
  return {
    ...rest,
    epssPercentile: epss_percentile ?? null,
  }
}

export interface FindingsSummary {
  open: number
  critical: number
  high: number
  medium: number
  low: number
  fixed_recent: number
  dismissed: number
  fixed_window_days: number
}

export async function listFindingsSummary(orgId: string): Promise<FindingsSummary> {
  if (!orgId) {
    throw new Error("findings-api: orgId is required")
  }
  const qs = new URLSearchParams({ org_id: orgId })
  return apiClient<FindingsSummary>(`/api/v1/findings/summary?${qs.toString()}`, {
    cache: "no-store",
  })
}

/** Reasons accepted by the backend. Keep in sync with backend/src/shared/lifecycle.VALID_DISMISS_REASONS. */
export const DISMISS_REASONS = [
  "Fix started",
  "Risk is tolerable",
  "Alert is inaccurate",
  "Vulnerable code is not used",
] as const

export type DismissReason = (typeof DISMISS_REASONS)[number]

export async function dismissFinding(
  findingId: number,
  reason: DismissReason,
  comment?: string,
): Promise<{ ok: true }> {
  return apiClient<{ ok: true }>(`/api/v1/findings/${findingId}/dismiss`, {
    method: "POST",
    body: JSON.stringify({ reason, comment }),
    headers: { "Content-Type": "application/json" },
  })
}

export async function bulkDismissFindings(
  ids: number[],
  reason: DismissReason,
  comment?: string,
): Promise<{ ok: true; updated: number }> {
  if (ids.length === 0) {
    throw new Error("findings-api: bulkDismissFindings requires at least one id")
  }
  return apiClient<{ ok: true; updated: number }>(`/api/v1/findings/bulk_dismiss`, {
    method: "POST",
    body: JSON.stringify({ ids, reason, comment }),
    headers: { "Content-Type": "application/json" },
  })
}

/** Update a finding's assignee. Pass `null` to clear. */
export async function updateFindingAssignee(
  findingId: number,
  assigneeUserId: string | null,
): Promise<{ ok: true; finding: Finding }> {
  const raw = await apiClient<{ ok: true; finding: RawFinding }>(
    `/api/v1/findings/${findingId}/assignee`,
    {
      method: "PATCH",
      body: JSON.stringify({ assignee_user_id: assigneeUserId }),
      headers: { "Content-Type": "application/json" },
    },
  )
  return { ok: raw.ok, finding: normalizeFinding(raw.finding) }
}

export interface AssignableUser {
  id: string
  username: string
  email: string
}

export async function listAssignableUsers(
  q: string | null = null,
  limit = 20,
): Promise<AssignableUser[]> {
  const qs = new URLSearchParams()
  if (q) qs.set("q", q)
  qs.set("limit", String(limit))
  const data = await apiClient<{ users: AssignableUser[] }>(
    `/api/v1/findings/assignable-users?${qs.toString()}`,
    { cache: "no-store" },
  )
  return data.users
}

export async function listFindings(
  params: ListFindingsParams,
): Promise<FindingsListResponse> {
  if (!params.orgId) {
    throw new Error("findings-api: orgId is required")
  }

  const qs = new URLSearchParams()
  qs.set("org_id", params.orgId)
  if (params.severity && params.severity.length > 0) {
    qs.set("severity", params.severity.join(","))
  }
  if (params.scanner && params.scanner.length > 0) {
    qs.set("scanner", params.scanner.join(","))
  }
  if (params.state && params.state.length > 0) {
    qs.set("state", params.state.join(","))
  }
  if (params.q) qs.set("q", params.q)
  if (params.cve) qs.set("cve", params.cve)
  if (params.repo) qs.set("repo", params.repo)
  if (params.sort) qs.set("sort", params.sort)
  if (params.direction) qs.set("direction", params.direction)
  if (params.first_seen_after) qs.set("first_seen_after", params.first_seen_after)
  if (params.cwe) qs.set("cwe", params.cwe)
  if (params.kev) qs.set("kev", "true")
  if (params.epss_min != null) qs.set("epss_min", String(params.epss_min))
  if (params.risk_score_min != null) qs.set("risk_score_min", String(params.risk_score_min))
  if (params.assignee) qs.set("assignee", params.assignee)
  if (params.limit != null) qs.set("limit", String(params.limit))
  if (params.page != null) qs.set("page", String(params.page))

  const url = `/api/v1/findings?${qs.toString()}`

  const raw = await apiClient<RawFindingsListResponse>(url, { cache: "no-store" })
  return {
    findings: raw.findings.map(normalizeFinding),
    next_cursor: raw.next_cursor,
    total_count: raw.total_count,
  }
}

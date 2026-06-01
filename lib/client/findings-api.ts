/**
 * TypeScript client for the aggregated findings REST API (Phase 55).
 *
 * Mirrors the fetch pattern used by other clients in lib/client/. Server
 * fields stay snake_case in the wire format; we expose a camelCase
 * `epssPercentile` mirror on each row so the EPSS column rendered by
 * EpssScoreCell (Phase 54) keeps working unchanged when the backend
 * starts populating it.
 */

export type FindingSeverity = "critical" | "high" | "medium" | "low"
export type FindingScanner = "deps" | "container" | "sast" | "secrets"
export type FindingState = "open" | "closed" | "dismissed" | "fixed"
export type FindingSort = "severity" | "created_at" | "updated_at"
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
}

export interface ListFindingsParams {
  orgId: string
  severity?: FindingSeverity[]
  scanner?: FindingScanner[]
  state?: FindingState[]
  q?: string
  cve?: string
  sort?: FindingSort
  direction?: FindingSortDirection
  limit?: number
  cursor?: string
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
  if (params.sort) qs.set("sort", params.sort)
  if (params.direction) qs.set("direction", params.direction)
  if (params.limit != null) qs.set("limit", String(params.limit))
  if (params.cursor) qs.set("cursor", params.cursor)

  const url = `/api/v1/findings?${qs.toString()}`

  const res = await fetch(url, { cache: "no-store" })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`findings-api: ${res.status} ${res.statusText} — ${text}`)
  }
  const raw = (await res.json()) as RawFindingsListResponse
  return {
    findings: raw.findings.map(normalizeFinding),
    next_cursor: raw.next_cursor,
    total_count: raw.total_count,
  }
}

/**
 * TypeScript client for the Phase 11 temporal correlation REST API.
 *
 * Endpoints are proxied through Next.js to the FastAPI backend at
 * /api/v1/temporal/*. Mirrors the pattern used in chains-api.ts.
 */

export interface TemporalSeriesPoint {
  bucket_start: string // ISO 8601
  bucket_size: string  // '1h' | '1d' | '1w'
  value: number
  dimension: Record<string, string>
}

export interface TopAuthor {
  author: string
  total: number
  by_severity: { critical: number; high: number; medium: number; low: number }
}

export interface MttrRow {
  group: string
  // median_seconds/p95_seconds come from the spec; backend actually returns avg_ms
  avg_ms: number
  sample_count: number
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`temporal-api: ${res.status} ${res.statusText} — ${text}`)
  }
  return res.json() as Promise<T>
}

export async function fetchTemporalSeries(params: {
  metric: string
  org_id: string
  bucket_size?: "1h" | "1d" | "1w"
  since_days?: number
  scanner_type?: string
  severity?: string
}): Promise<TemporalSeriesPoint[]> {
  const qs = new URLSearchParams({ metric: params.metric, org_id: params.org_id })
  if (params.bucket_size) qs.set("bucket_size", params.bucket_size)
  if (params.since_days != null) qs.set("since_days", String(params.since_days))
  if (params.scanner_type) qs.set("scanner_type", params.scanner_type)
  if (params.severity) qs.set("severity", params.severity)

  const data = await fetchJson<{ series: TemporalSeriesPoint[] } | TemporalSeriesPoint[]>(
    `/api/v1/temporal/series?${qs.toString()}`,
  )
  // Backend wraps in { series: [...] }; accept bare array too for resilience
  const raw = Array.isArray(data) ? data : (data as { series: TemporalSeriesPoint[] }).series ?? []

  // Attach bucket_size from params so callers don't need to track it separately;
  // spread p first so we can safely override bucket_size without a TS duplicate-key error
  return raw.map((p) => ({ ...p, bucket_size: params.bucket_size ?? "1d" }))
}

// Backend response shape for /top-authors
interface TopAuthorsResponse {
  org_id: string
  since_days: number
  authors: Array<{
    author: string
    total: number
    breakdown: Record<string, number>
  }>
}

export async function fetchTopAuthors(params: {
  org_id: string
  since_days?: number
  limit?: number
}): Promise<TopAuthor[]> {
  const qs = new URLSearchParams({ org_id: params.org_id })
  if (params.since_days != null) qs.set("since_days", String(params.since_days))
  if (params.limit != null) qs.set("limit", String(params.limit))

  const data = await fetchJson<TopAuthorsResponse>(`/api/v1/temporal/top-authors?${qs.toString()}`)

  return (data.authors ?? []).map((a) => ({
    author: a.author,
    total: a.total,
    by_severity: {
      critical: a.breakdown?.critical ?? 0,
      high: a.breakdown?.high ?? 0,
      medium: a.breakdown?.medium ?? 0,
      low: a.breakdown?.low ?? 0,
    },
  }))
}

// Backend response shape for /mttr
interface MttrResponse {
  org_id: string
  since_days: number
  group_by: string
  mttr: Array<{
    [groupKey: string]: string | number
    avg_ms: number
    sample_count: number
  }>
}

export async function fetchMttr(params: {
  org_id: string
  since_days?: number
  group_by?: "scanner_type" | "severity"
}): Promise<MttrRow[]> {
  const qs = new URLSearchParams({ org_id: params.org_id })
  if (params.since_days != null) qs.set("since_days", String(params.since_days))
  if (params.group_by) qs.set("group_by", params.group_by)

  const data = await fetchJson<MttrResponse>(`/api/v1/temporal/mttr?${qs.toString()}`)

  const groupKey = data.group_by ?? "scanner_type"
  return (data.mttr ?? []).map((row) => ({
    group: String(row[groupKey] ?? "unknown"),
    avg_ms: row.avg_ms ?? 0,
    sample_count: row.sample_count ?? 0,
  }))
}

/**
 * TypeScript client for the repos asset management REST API (Phase 27).
 *
 * All endpoints proxy through Next.js to the FastAPI backend at
 * /api/v1/repos. Mirrors the pattern used in chains-api.ts.
 */

export interface RepoSummary {
  repo_id: string
  org: string
  repo: string
  last_scanned_sha?: string | null
  manifest_set_hash?: string | null
  last_scanned_at?: string | null
  findings_count_by_severity: { critical: number; high: number; medium: number; low: number }
  chains_count: number
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

export interface ChainRow {
  id: string
  chain_type: string
  severity: string
  status: string
  created_at: string
}

export interface RepoDetail extends RepoSummary {
  scan_history: ScanRunRow[]
  active_findings: FindingRow[]
  attached_chains: ChainRow[]
  default_branch?: string | null
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`repos-api: ${res.status} ${res.statusText} — ${text}`)
  }
  return res.json() as Promise<T>
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
  const data = await fetchJson<{ repos: RepoSummary[] }>(`/api/v1/repos${qs ? `?${qs}` : ""}`)
  return data.repos ?? []
}

export async function getRepo(repoId: string): Promise<RepoDetail | null> {
  try {
    return await fetchJson<RepoDetail>(`/api/v1/repos/${encodeURIComponent(repoId)}`)
  } catch (err: unknown) {
    if (err instanceof Error && err.message.includes("404")) return null
    throw err
  }
}

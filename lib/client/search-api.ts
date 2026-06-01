/**
 * TypeScript client for the global search REST API (Phase 28).
 *
 * Mirrors the fetch pattern used by other clients in this package.
 * Uses AbortController so in-flight requests are cancelled when the
 * caller supersedes them with a newer query.
 */

export interface SearchHit {
  type: string
  id: string
  title: string
  subtitle?: string
  href: string
  score: number
  metadata: Record<string, unknown>
}

export interface SearchResults {
  query: string
  total: number
  grouped: Record<string, SearchHit[]>
  duration_ms: number
}

export interface SearchOptions {
  scopes?: string[]
  limit?: number
  signal?: AbortSignal
}

export async function search(
  query: string,
  opts: SearchOptions = {},
): Promise<SearchResults> {
  const { scopes, limit = 50, signal } = opts

  const qs = new URLSearchParams()
  qs.set("q", query)
  if (scopes && scopes.length > 0) {
    qs.set("scope", scopes.join(","))
  }
  if (limit !== 50) {
    qs.set("limit", String(limit))
  }

  const res = await fetch(`/api/v1/search?${qs.toString()}`, {
    cache: "no-store",
    signal,
  })

  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`search-api: ${res.status} ${res.statusText} — ${text}`)
  }

  return res.json() as Promise<SearchResults>
}

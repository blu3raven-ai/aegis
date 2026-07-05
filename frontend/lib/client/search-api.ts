/** Client for the global search surface. Supports AbortSignal-based cancellation. */

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

interface GlobalSearchResponse {
  findings: {
    globalSearch: {
      query: string
      total: number
      durationMs: number
      findings: SearchHit[]
      repos: SearchHit[]
      auditEvents: SearchHit[]
      destinations: SearchHit[]
    }
  }
}

const CSRF_COOKIE_NAME = "__Host-csrf"

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=")
    if (k === CSRF_COOKIE_NAME) return rest.join("=")
  }
  return null
}

const QUERY = `query GlobalSearch($q: String!, $scopes: [String!], $limit: Int!) {
  findings {
    globalSearch(q: $q, scopes: $scopes, limit: $limit) {
      query
      total
      durationMs
      findings { type id title subtitle href score metadata }
      repos { type id title subtitle href score metadata }
      auditEvents { type id title subtitle href score metadata }
      destinations { type id title subtitle href score metadata }
    }
  }
}`

export async function search(
  query: string,
  opts: SearchOptions = {},
): Promise<SearchResults> {
  const { scopes, limit = 50, signal } = opts

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) headers["X-CSRF-Token"] = csrf

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({
      operationName: "GlobalSearch",
      query: QUERY,
      variables: {
        q: query,
        scopes: scopes && scopes.length > 0 ? scopes : null,
        limit,
      },
    }),
    signal,
    credentials: "include",
  })

  if (!res.ok) throw new Error(`Search failed: ${res.status}`)

  const body = (await res.json()) as {
    data?: GlobalSearchResponse
    errors?: { message: string }[]
  }
  if (body.errors && body.errors.length > 0) {
    throw new Error(body.errors[0].message)
  }
  if (!body.data) {
    throw new Error("Search returned no data")
  }

  const data = body.data.findings.globalSearch
  return {
    query: data.query,
    total: data.total,
    duration_ms: data.durationMs,
    grouped: {
      findings: data.findings,
      repos: data.repos,
      audit_events: data.auditEvents,
      destinations: data.destinations,
    },
  }
}

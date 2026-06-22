/** Client for the per-user saved-views surface. */

export interface SavedView {
  id: string
  surface: string
  name: string
  url_state: Record<string, string>
  is_default: boolean
  created_at: string | null
  updated_at: string | null
}

const BASE = "/api/v1/settings/saved-views"
const CSRF_COOKIE_NAME = "__Host-csrf"

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=")
    if (k === CSRF_COOKIE_NAME) return rest.join("=")
  }
  return null
}

export class GqlError extends Error {
  code: string | null
  constructor(message: string, code: string | null) {
    super(message)
    this.code = code
  }
}

async function gqlFetch<T>(operationName: string, query: string, variables: Record<string, unknown>): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) headers["X-CSRF-Token"] = csrf

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ operationName, query, variables }),
    credentials: "include",
  })
  const body = (await res.json()) as {
    data?: T
    errors?: { message: string; extensions?: { code?: string } }[]
  }
  if (body.errors && body.errors.length > 0) {
    const first = body.errors[0]
    throw new GqlError(first.message, first.extensions?.code ?? null)
  }
  if (!body.data) {
    throw new GqlError(`${operationName} returned no data`, null)
  }
  return body.data
}

interface GqlSavedView {
  id: string
  surface: string
  name: string
  urlState: Record<string, string>
  isDefault: boolean
  createdAt: string | null
  updatedAt: string | null
}

const SAVED_VIEWS_QUERY = `query SavedViews($surface: String!) {
  settings {
    savedViews(surface: $surface) {
      id
      surface
      name
      urlState
      isDefault
      createdAt
      updatedAt
    }
  }
}`

function adapt(v: GqlSavedView): SavedView {
  return {
    id: v.id,
    surface: v.surface,
    name: v.name,
    url_state: v.urlState,
    is_default: v.isDefault,
    created_at: v.createdAt,
    updated_at: v.updatedAt,
  }
}

export async function listSavedViews(surface: string): Promise<SavedView[]> {
  const data = await gqlFetch<{ settings: { savedViews: GqlSavedView[] } }>(
    "SavedViews",
    SAVED_VIEWS_QUERY,
    { surface },
  )
  return data.settings.savedViews.map(adapt)
}

export async function createSavedView(input: { surface: string; name: string; url_state: Record<string, string> }): Promise<SavedView> {
  const r = await fetch(BASE, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  })
  if (!r.ok) throw new Error(`create saved view failed: ${r.status}`)
  return r.json()
}

export async function updateSavedView(id: string, patch: { name?: string; url_state?: Record<string, string> }): Promise<SavedView> {
  const r = await fetch(`${BASE}/${encodeURIComponent(id)}`, {
    method: "PATCH",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(patch),
  })
  if (!r.ok) throw new Error(`update saved view failed: ${r.status}`)
  return r.json()
}

export async function deleteSavedView(id: string): Promise<void> {
  const r = await fetch(`${BASE}/${encodeURIComponent(id)}`, {
    method: "DELETE",
    credentials: "include",
  })
  if (!r.ok) throw new Error(`delete saved view failed: ${r.status}`)
}

export async function setSavedViewDefault(id: string): Promise<SavedView> {
  const r = await fetch(`${BASE}/${encodeURIComponent(id)}`, {
    method: "PATCH",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ set_default: true }),
  })
  if (!r.ok) throw new Error(`set default failed: ${r.status}`)
  return r.json()
}

/**
 * TypeScript client for the activity feed GraphQL queries.
 */

export interface ActivityEvent {
  id: string
  type: string
  occurred_at: string
  actor: string | null
  repo_id: string | null
  summary: string
  payload: Record<string, unknown>
}

export interface ListActivityParams {
  types?: string[]
  repo_id?: string
  since?: string
  until?: string
  cursor?: string
  limit?: number
}

export interface ListActivityResponse {
  events: ActivityEvent[]
  next_cursor: string | null
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
  const body = (await res.json()) as { data?: T; errors?: { message: string }[] }
  if (body.errors && body.errors.length > 0) {
    throw new Error(body.errors[0].message)
  }
  if (!body.data) {
    throw new Error(`${operationName} returned no data`)
  }
  return body.data
}

interface GqlActivityEvent {
  id: string
  type: string
  occurredAt: string
  actor: string | null
  repoId: string | null
  summary: string
  payloadJson: string
}

interface GqlActivityResponse {
  history: {
    events: {
      events: GqlActivityEvent[]
      nextCursor: string | null
    }
  }
}

interface GqlActivityTypesResponse {
  history: {
    types: string[]
  }
}

const ACTIVITY_QUERY = `query Activity(
  $types: [String!],
  $repoId: String,
  $since: String,
  $until: String,
  $limit: Int,
  $cursor: String
) {
  history {
    events(
      types: $types,
      repoId: $repoId,
      since: $since,
      until: $until,
      limit: $limit,
      cursor: $cursor
    ) {
      events {
        id
        type
        occurredAt
        actor
        repoId
        summary
        payloadJson
      }
      nextCursor
    }
  }
}`

const ACTIVITY_TYPES_QUERY = `query ActivityTypes {
  history { types }
}`

function parsePayload(json: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(json)
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>
    }
  } catch {
    // fall through
  }
  return {}
}

export async function listActivity(
  params: ListActivityParams = {},
): Promise<ListActivityResponse> {
  const data = await gqlFetch<GqlActivityResponse>("Activity", ACTIVITY_QUERY, {
    types: params.types && params.types.length > 0 ? params.types : null,
    repoId: params.repo_id ?? null,
    since: params.since ?? null,
    until: params.until ?? null,
    limit: params.limit ?? null,
    cursor: params.cursor ?? null,
  })

  return {
    events: data.history.events.events.map((e) => ({
      id: e.id,
      type: e.type,
      occurred_at: e.occurredAt,
      actor: e.actor,
      repo_id: e.repoId,
      summary: e.summary,
      payload: parsePayload(e.payloadJson),
    })),
    next_cursor: data.history.events.nextCursor,
  }
}

export async function listActivityTypes(): Promise<string[]> {
  const data = await gqlFetch<GqlActivityTypesResponse>("ActivityTypes", ACTIVITY_TYPES_QUERY, {})
  return data.history.types
}

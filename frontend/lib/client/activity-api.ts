/**
 * TypeScript client for the activity feed GraphQL queries.
 */

import { gqlFetch } from "./graphql-fetch.ts"

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

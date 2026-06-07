/**
 * TypeScript client for the activity feed REST API (Phase 52).
 *
 * Mirrors the fetch pattern used by other clients in lib/client/.
 */

import { apiClient } from "./api-client.ts"

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

export async function listActivity(
  params: ListActivityParams = {},
): Promise<ListActivityResponse> {
  const qs = new URLSearchParams()
  if (params.types && params.types.length > 0) {
    qs.set("types", params.types.join(","))
  }
  if (params.repo_id) qs.set("repo_id", params.repo_id)
  if (params.since) qs.set("since", params.since)
  if (params.until) qs.set("until", params.until)
  if (params.cursor) qs.set("cursor", params.cursor)
  if (params.limit != null) qs.set("limit", String(params.limit))

  const query = qs.toString()
  const url = `/api/v1/activity${query ? `?${query}` : ""}`

  return apiClient<ListActivityResponse>(url)
}

export async function listActivityTypes(): Promise<string[]> {
  const data = await apiClient<{ types: string[] }>("/api/v1/activity/types")
  return data.types
}

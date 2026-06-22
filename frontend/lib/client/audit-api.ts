/** Client for the audit-log surface. */

import { apiClient } from "./api-client.ts"

export interface AuditEvent {
  id: number
  actor_id?: string
  actor_email?: string
  actor_role?: string
  action: string
  resource_type?: string
  resource_id?: string
  request_method?: string
  request_path?: string
  request_ip?: string
  user_agent?: string
  changes?: Record<string, unknown>
  metadata?: Record<string, unknown>
  status_code?: number
  occurred_at?: string
}

export interface AuditQueryFilters {
  action?: string
  actor_id?: string
  resource_type?: string
  resource_id?: string
  since?: string
  until?: string
  limit?: number
  offset?: number
}

export interface AuditEventsResponse {
  events: AuditEvent[]
  total_count: number
  limit: number
  offset: number
}

function buildQuery(filters: AuditQueryFilters): string {
  const params = new URLSearchParams()
  if (filters.action) params.set("action", filters.action)
  if (filters.actor_id) params.set("actor_id", filters.actor_id)
  if (filters.resource_type) params.set("resource_type", filters.resource_type)
  if (filters.resource_id) params.set("resource_id", filters.resource_id)
  if (filters.since) params.set("since", filters.since)
  if (filters.until) params.set("until", filters.until)
  params.set("limit", String(filters.limit ?? 100))
  params.set("offset", String(filters.offset ?? 0))
  return params.toString()
}

/** Page through audit events. Defaults: limit=100, offset=0. */
export async function listAuditEvents(
  filters: AuditQueryFilters,
): Promise<AuditEventsResponse> {
  const qs = buildQuery(filters)
  return apiClient<AuditEventsResponse>(`/api/v1/settings/audit/events?${qs}`)
}

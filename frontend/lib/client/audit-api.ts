import { apiClient } from "./api-client.ts"

export interface AuditEvent {
  id: number
  org_id: string
  actor_id?: string
  actor_email?: string
  actor_role?: string
  action: string
  resource_type: string
  resource_id?: string
  request_method?: string
  request_path?: string
  request_ip?: string
  user_agent?: string
  changes?: Record<string, unknown>
  metadata?: Record<string, unknown>
  status_code?: number
  occurred_at: string
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

interface AuditEventsResponse {
  events: AuditEvent[]
  total: number
  has_more: boolean
}

export async function listAuditEvents(filters: AuditQueryFilters): Promise<AuditEventsResponse> {
  const qs = new URLSearchParams()
  if (filters.action) qs.set("action", filters.action)
  if (filters.actor_id) qs.set("actor_id", filters.actor_id)
  if (filters.resource_type) qs.set("resource_type", filters.resource_type)
  if (filters.resource_id) qs.set("resource_id", filters.resource_id)
  if (filters.since) qs.set("since", filters.since)
  if (filters.until) qs.set("until", filters.until)
  if (filters.limit != null) qs.set("limit", String(filters.limit))
  if (filters.offset != null) qs.set("offset", String(filters.offset))

  return apiClient<AuditEventsResponse>(`/api/v1/audit/events?${qs.toString()}`)
}

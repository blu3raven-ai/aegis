/**
 * TypeScript client for the notification destinations REST API (Phase 13).
 *
 * All endpoints are proxied through /api/v1/notifications/destinations.
 * Mirrors the pattern used in chains-api.ts and temporal-api.ts.
 */

export interface NotificationDestination {
  id: number
  org_id: string
  destination_type: "slack" | "webhook" | "email"
  name: string
  config: Record<string, unknown>
  enabled: boolean
  event_filter: {
    event_types?: string[]
    min_severity?: string
  }
  created_at: string
  updated_at: string
}

export interface NotificationDelivery {
  id: number
  destination_id: number
  event_id: string
  event_type: string
  status: "pending" | "delivered" | "failed" | "retry"
  payload_summary?: string
  response_code?: number
  error?: string
  attempted_at: string
}

export interface TestSendResult {
  status: "delivered" | "failed"
  channel: string
  latency_ms: number
  error?: string
}

export type CreateDestinationPayload = {
  org_id: string
  destination_type: "slack" | "webhook" | "email"
  name: string
  config: Record<string, unknown>
  enabled?: boolean
  event_filter?: { event_types?: string[]; min_severity?: string }
}

export type UpdateDestinationPayload = {
  name?: string
  config?: Record<string, unknown>
  enabled?: boolean
  event_filter?: { event_types?: string[]; min_severity?: string }
}

const BASE = "/api/v1/notifications/destinations"

class DestinationsApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = "DestinationsApiError"
    this.status = status
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  if (!res.ok) {
    const body = await res.text().catch(() => "")
    let detail = body
    try {
      const parsed = JSON.parse(body) as { detail?: string }
      if (parsed.detail) detail = parsed.detail
    } catch {
      // use raw text
    }
    throw new DestinationsApiError(
      `destinations-api: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`,
      res.status,
    )
  }
  // 204 No Content
  if (res.status === 204) return undefined as unknown as T
  return res.json() as Promise<T>
}

export async function listDestinations(orgId: string): Promise<NotificationDestination[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await fetchJson<{ destinations: NotificationDestination[] }>(
    `${BASE}?${qs.toString()}`,
  )
  return data.destinations ?? []
}

export async function createDestination(
  payload: CreateDestinationPayload,
): Promise<NotificationDestination> {
  return fetchJson<NotificationDestination>(BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
}

export async function updateDestination(
  id: number,
  payload: UpdateDestinationPayload,
): Promise<NotificationDestination> {
  return fetchJson<NotificationDestination>(`${BASE}/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
}

export async function deleteDestination(id: number): Promise<void> {
  await fetchJson<void>(`${BASE}/${id}`, { method: "DELETE" })
}

export async function listDeliveries(
  destinationId: number,
  limit = 50,
): Promise<NotificationDelivery[]> {
  const qs = new URLSearchParams({ limit: String(limit) })
  const data = await fetchJson<{ deliveries: NotificationDelivery[] }>(
    `${BASE}/${destinationId}/deliveries?${qs.toString()}`,
  )
  return data.deliveries ?? []
}

export async function testDestination(
  destinationId: number,
  orgId: string,
): Promise<TestSendResult> {
  const qs = new URLSearchParams({ org_id: orgId })
  return fetchJson<TestSendResult>(`${BASE}/${destinationId}/test?${qs.toString()}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  })
}

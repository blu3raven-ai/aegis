/**
 * TypeScript client for the notification destinations REST API (Phase 13).
 *
 * All endpoints are proxied through /api/v1/notifications/destinations.
 */

import { apiClient } from "./api-client.ts"

export interface NotificationDestination {
  id: number
  org_id: string
  destination_type: string
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
  destination_type: string
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

export async function listDestinations(orgId: string): Promise<NotificationDestination[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ destinations: NotificationDestination[] }>(
    `${BASE}?${qs.toString()}`,
  )
  return data.destinations ?? []
}

export async function createDestination(
  payload: CreateDestinationPayload,
): Promise<NotificationDestination> {
  return apiClient<NotificationDestination>(BASE, {
    method: "POST",
    body: payload,
  })
}

export async function updateDestination(
  id: number,
  payload: UpdateDestinationPayload,
): Promise<NotificationDestination> {
  return apiClient<NotificationDestination>(`${BASE}/${id}`, {
    method: "PUT",
    body: payload,
  })
}

export async function deleteDestination(id: number): Promise<void> {
  await apiClient<void>(`${BASE}/${id}`, { method: "DELETE" })
}

export async function listDeliveries(
  destinationId: number,
  limit = 50,
): Promise<NotificationDelivery[]> {
  const qs = new URLSearchParams({ limit: String(limit) })
  const data = await apiClient<{ deliveries: NotificationDelivery[] }>(
    `${BASE}/${destinationId}/deliveries?${qs.toString()}`,
  )
  return data.deliveries ?? []
}

export async function testDestination(
  destinationId: number,
  orgId: string,
): Promise<TestSendResult> {
  const qs = new URLSearchParams({ org_id: orgId })
  return apiClient<TestSendResult>(`${BASE}/${destinationId}/test?${qs.toString()}`, {
    method: "POST",
  })
}

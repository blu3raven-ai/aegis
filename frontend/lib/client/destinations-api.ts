/** Client for notification destinations and their delivery history. */

import { apiClient } from "./api-client.ts"

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

export interface NotificationDestination {
  id: number
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

const NOTIFICATION_DESTINATIONS_QUERY = `query NotificationDestinations {
  notifications {
    destinations {
      id
      destinationType
      name
      config
      enabled
      eventFilter
      createdAt
      updatedAt
    }
  }
}`

interface GqlNotificationDestination {
  id: number
  destinationType: string
  name: string
  config: Record<string, unknown>
  enabled: boolean
  eventFilter: NotificationDestination["event_filter"]
  createdAt: string | null
  updatedAt: string | null
}

interface GqlNotificationDestinationsResponse {
  notifications: { destinations: GqlNotificationDestination[] }
}

function fromGqlDestination(d: GqlNotificationDestination): NotificationDestination {
  return {
    id: d.id,
    destination_type: d.destinationType,
    name: d.name,
    config: d.config ?? {},
    enabled: d.enabled,
    event_filter: d.eventFilter ?? {},
    created_at: d.createdAt ?? "",
    updated_at: d.updatedAt ?? "",
  }
}

export async function listDestinations(): Promise<NotificationDestination[]> {
  const data = await gqlFetch<GqlNotificationDestinationsResponse>(
    "NotificationDestinations",
    NOTIFICATION_DESTINATIONS_QUERY,
    {},
  )
  return data.notifications.destinations.map(fromGqlDestination)
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

const NOTIFICATION_DELIVERIES_QUERY = `query NotificationDeliveries($destinationId: Int!, $limit: Int) {
  notifications {
    deliveries(destinationId: $destinationId, limit: $limit) {
      id
      destinationId
      eventId
      eventType
      status
      payloadSummary
      responseCode
      error
      attemptedAt
    }
  }
}`

interface GqlNotificationDelivery {
  id: string
  destinationId: number
  eventId: string
  eventType: string
  status: string
  payloadSummary?: string | null
  responseCode?: number | null
  error?: string | null
  attemptedAt?: string | null
}

interface GqlNotificationDeliveriesResponse {
  notifications: { deliveries: GqlNotificationDelivery[] }
}

function fromGqlDelivery(d: GqlNotificationDelivery): NotificationDelivery {
  return {
    id: Number(d.id),
    destination_id: d.destinationId,
    event_id: d.eventId,
    event_type: d.eventType,
    status: d.status as NotificationDelivery["status"],
    payload_summary: d.payloadSummary ?? undefined,
    response_code: d.responseCode ?? undefined,
    error: d.error ?? undefined,
    attempted_at: d.attemptedAt ?? "",
  }
}

export async function listDeliveries(
  destinationId: number,
  limit = 50,
): Promise<NotificationDelivery[]> {
  const data = await gqlFetch<GqlNotificationDeliveriesResponse>(
    "NotificationDeliveries",
    NOTIFICATION_DELIVERIES_QUERY,
    { destinationId, limit },
  )
  return data.notifications.deliveries.map(fromGqlDelivery)
}

export async function testDestination(
  destinationId: number,
): Promise<TestSendResult> {
  return apiClient<TestSendResult>(`${BASE}/${destinationId}/test`, {
    method: "POST",
  })
}

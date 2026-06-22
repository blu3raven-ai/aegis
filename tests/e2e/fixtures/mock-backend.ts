/**
 * Shared mocks for new product surfaces: Findings, Notifications config,
 * and Audit log.
 *
 * Each helper intercepts only the specific endpoints it owns — never
 * auth endpoints (/auth/login, /auth/me).
 */

import type { Page } from "@playwright/test"

// ── Shared mock data ──────────────────────────────────────────────────────────

export const MOCK_DESTINATIONS = [
  {
    id: 1,
    org_id: "example-org",
    destination_type: "slack",
    name: "Security alerts",
    config: { webhook_url: "https://hooks.slack.com/services/T000/B000/xxxx" },
    enabled: true,
    event_filter: { min_severity: "high" },
    created_at: "2026-04-01T00:00:00Z",
    updated_at: "2026-04-01T00:00:00Z",
  },
]

export const MOCK_AUDIT_EVENTS = [
  {
    id: 1,
    org_id: "example-org",
    actor_id: "u1",
    actor_email: "admin@example-org.com",
    actor_role: "owner",
    action: "user.created",
    resource_type: "user",
    resource_id: "u2",
    request_method: "POST",
    request_path: "/api/v1/users",
    request_ip: "127.0.0.1",
    status_code: 201,
    occurred_at: "2026-05-01T10:00:00Z",
    changes: { before: null, after: { role: "viewer", email: "newuser@example-org.com" } },
  },
  {
    id: 2,
    org_id: "example-org",
    actor_id: "u1",
    actor_email: "admin@example-org.com",
    actor_role: "owner",
    action: "destination.created",
    resource_type: "notification_destination",
    resource_id: "1",
    request_method: "POST",
    request_path: "/api/v1/notifications/destinations",
    request_ip: "127.0.0.1",
    status_code: 201,
    occurred_at: "2026-05-02T11:00:00Z",
    changes: null,
  },
]

// ── Per-surface mock helpers ──────────────────────────────────────────────────

/** Mock the notification destinations API endpoints. */
export async function mockDestinationsAPI(
  page: Page,
  opts?: { empty?: boolean; destinations?: typeof MOCK_DESTINATIONS },
) {
  const rows = opts?.empty ? [] : (opts?.destinations ?? MOCK_DESTINATIONS)

  await page.route("**/api/v1/notifications/destinations**", (route, request) => {
    const url = new URL(request.url())
    const pathParts = url.pathname.split("/").filter(Boolean)
    const destIdx = pathParts.indexOf("destinations")
    const resourceId = destIdx >= 0 && pathParts.length > destIdx + 1
      ? pathParts[destIdx + 1]
      : null

    if (request.method() === "GET" && !resourceId) {
      return route.fulfill({ json: { destinations: rows } })
    }

    if (request.method() === "POST" && !resourceId) {
      // Simulate create
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>
      const created = {
        id: 99,
        org_id: "example-org",
        destination_type: body.destination_type ?? "slack",
        name: body.name ?? "New destination",
        config: body.config ?? {},
        enabled: true,
        event_filter: body.event_filter ?? {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }
      return route.fulfill({ status: 201, json: created })
    }

    if (request.method() === "PUT") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>
      const existing = rows.find((r) => String(r.id) === resourceId) ?? rows[0]
      return route.fulfill({
        json: { ...existing, ...body, updated_at: new Date().toISOString() },
      })
    }

    if (request.method() === "DELETE") {
      return route.fulfill({ status: 204, body: "" })
    }

    // GET deliveries: /destinations/<id>/deliveries
    if (request.method() === "GET" && resourceId) {
      return route.fulfill({ json: { deliveries: [] } })
    }

    return route.continue()
  })
}

/** Mock the audit events REST endpoint. */
export async function mockAuditAPI(
  page: Page,
  opts?: { empty?: boolean; events?: typeof MOCK_AUDIT_EVENTS },
) {
  const events = opts?.empty ? [] : (opts?.events ?? MOCK_AUDIT_EVENTS)

  await page.route("**/api/v1/audit/events**", (route) =>
    route.fulfill({
      json: { events, total: events.length, has_more: false },
    })
  )
}

/** Intercept the SSE stream so tests don't block on it. */
export async function mockSSE(page: Page) {
  await page.route("**/api/v1/history/events/stream**", (route) =>
    route.fulfill({
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
      body: "",
    })
  )
}


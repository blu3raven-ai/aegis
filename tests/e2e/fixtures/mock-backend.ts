/**
 * Shared mocks for new product surfaces: Findings, Chains, Insights,
 * Notifications config, and Audit log.
 *
 * Each helper intercepts only the specific endpoints it owns — never
 * auth endpoints (/api/login, /api/me).
 */

import type { Page } from "@playwright/test"

// ── Shared mock data ──────────────────────────────────────────────────────────

export const MOCK_CHAIN = {
  id: "chain-01",
  org_id: "example-org",
  chain_type: "RCE-reachable",
  severity: "critical",
  status: "open",
  created_at: "2026-05-01T00:00:00Z",
  last_updated_at: "2026-05-29T08:00:00Z",
  edges: [],
}

export const MOCK_CHAINS = [
  MOCK_CHAIN,
  {
    id: "chain-02",
    org_id: "example-org",
    chain_type: "data-exfil",
    severity: "critical",
    status: "open",
    created_at: "2026-05-02T00:00:00Z",
    last_updated_at: "2026-05-28T08:00:00Z",
    edges: [],
  },
  {
    id: "chain-03",
    org_id: "example-org",
    chain_type: "privilege-escalation",
    severity: "high",
    status: "acknowledged",
    created_at: "2026-05-03T00:00:00Z",
    last_updated_at: "2026-05-27T08:00:00Z",
    edges: [],
  },
]

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

export const MOCK_TEMPORAL_SERIES = [
  { bucket_start: "2026-05-01T00:00:00Z", bucket_size: "1d", value: 12, dimension: {} },
  { bucket_start: "2026-05-02T00:00:00Z", bucket_size: "1d", value: 8,  dimension: {} },
  { bucket_start: "2026-05-03T00:00:00Z", bucket_size: "1d", value: 15, dimension: {} },
]

export const MOCK_TOP_AUTHORS = [
  { author: "alice", total: 24, by_severity: { critical: 4, high: 10, medium: 8, low: 2 } },
  { author: "bob",   total: 16, by_severity: { critical: 1, high:  6, medium: 7, low: 2 } },
]

export const MOCK_MTTR_ROWS = [
  { group: "deps",    avg_ms: 345_600_000, sample_count: 42 },
  { group: "sast",    avg_ms: 172_800_000, sample_count: 31 },
  { group: "secrets", avg_ms: 86_400_000,  sample_count: 18 },
]

// ── Per-surface mock helpers ──────────────────────────────────────────────────

/** Mock the chains list + individual chain GET endpoints. */
export async function mockChainsAPI(page: Page, overrides?: { chains?: typeof MOCK_CHAINS }) {
  const chains = overrides?.chains ?? MOCK_CHAINS

  await page.route("**/api/v1/chains**", (route, request) => {
    // Individual chain detail: /api/v1/chains/<id>
    const url = new URL(request.url())
    const pathParts = url.pathname.split("/").filter(Boolean)
    const chainIdx = pathParts.indexOf("chains")
    const id = chainIdx >= 0 && pathParts.length > chainIdx + 1 ? pathParts[chainIdx + 1] : null

    if (id && !url.searchParams.has("org_id")) {
      const found = chains.find((c) => c.id === id) ?? { ...MOCK_CHAIN, id }
      return route.fulfill({ json: found })
    }
    // List
    return route.fulfill({ json: { chains } })
  })
}

/** Mock the Insights temporal API endpoints. */
export async function mockInsightsAPI(page: Page) {
  await page.route("**/api/v1/temporal/series**", (route) =>
    route.fulfill({ json: { series: MOCK_TEMPORAL_SERIES } })
  )

  await page.route("**/api/v1/temporal/top-authors**", (route) =>
    route.fulfill({
      json: {
        org_id: "example-org",
        since_days: 30,
        authors: MOCK_TOP_AUTHORS.map((a) => ({
          author: a.author,
          total: a.total,
          breakdown: a.by_severity,
        })),
      },
    })
  )

  await page.route("**/api/v1/temporal/mttr**", (route) =>
    route.fulfill({
      json: {
        org_id: "example-org",
        since_days: 30,
        group_by: "scanner_type",
        mttr: MOCK_MTTR_ROWS.map((r) => ({ scanner_type: r.group, avg_ms: r.avg_ms, sample_count: r.sample_count })),
      },
    })
  )

  // AnomaliesPanel fetches its own endpoint
  await page.route("**/api/v1/temporal/anomalies**", (route) =>
    route.fulfill({ json: { anomalies: [] } })
  )
}

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
  await page.route("**/api/events/stream**", (route) =>
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

/** Mock the license endpoint to avoid unhandled rejections in chain-detail page. */
export async function mockLicenseAPI(page: Page, tier: "community" | "enterprise" = "community") {
  await page.route("**/api/license**", (route) =>
    route.fulfill({ json: { tier, status: "active" } })
  )
}

/**
 * TypeScript client for the SLA policy REST API (Phase 47).
 *
 * Mirrors the pattern used in notification-rules-api.ts and destinations-api.ts.
 */

const BASE = "/api/v1"

export interface SlaPolicy {
  id: number | null
  org_id: string
  severity: "critical" | "high" | "medium" | "low"
  deadline_days: number
  enabled: boolean
  created_at: string | null
  updated_at: string | null
}

export interface SeverityBreachStat {
  open: number
  breached: number
  breached_pct: number
}

export interface BreachSummary {
  critical: SeverityBreachStat
  high: SeverityBreachStat
  medium: SeverityBreachStat
  low: SeverityBreachStat
}

export type UpdateSlaPolicyPayload = {
  deadline_days: number
  enabled: boolean
}

export class SlaApiError extends Error {
  readonly status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = "SlaApiError"
    this.status = status
  }
}

async function fetchJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const res = await fetch(input, init)
  if (!res.ok) {
    let detail = ""
    try {
      const body = await res.json()
      detail = body?.detail ?? ""
    } catch {
      // ignore parse failure
    }
    throw new SlaApiError(
      `sla-api: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`,
      res.status,
    )
  }
  if (res.status === 204) return undefined as unknown as T
  return res.json() as Promise<T>
}

export async function listSlaPolicies(orgId: string): Promise<SlaPolicy[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await fetchJson<{ policies: SlaPolicy[] }>(`${BASE}/sla-policies?${qs}`)
  return data.policies ?? []
}

export async function updateSlaPolicy(
  orgId: string,
  severity: string,
  payload: UpdateSlaPolicyPayload,
): Promise<SlaPolicy> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await fetchJson<{ policy: SlaPolicy }>(`${BASE}/sla-policies/${severity}?${qs}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
  return data.policy
}

export async function getBreachSummary(orgId: string): Promise<BreachSummary> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await fetchJson<{ summary: BreachSummary }>(`${BASE}/sla/breach-summary?${qs}`)
  return data.summary
}

export async function triggerRecompute(orgId: string): Promise<{ ok: boolean; updated: number }> {
  const qs = new URLSearchParams({ org_id: orgId })
  return fetchJson<{ ok: boolean; updated: number }>(`${BASE}/sla/recompute?${qs}`, {
    method: "POST",
  })
}

/**
 * TypeScript client for the SLA policy REST API (Phase 47).
 *
 * Mirrors the pattern used in notification-rules-api.ts and destinations-api.ts.
 */

import { apiClient } from "./api-client.ts"

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

export async function listSlaPolicies(orgId: string): Promise<SlaPolicy[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ policies: SlaPolicy[] }>(`${BASE}/sla-policies?${qs}`)
  return data.policies ?? []
}

export async function updateSlaPolicy(
  orgId: string,
  severity: string,
  payload: UpdateSlaPolicyPayload,
): Promise<SlaPolicy> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ policy: SlaPolicy }>(`${BASE}/sla-policies/${severity}?${qs}`, {
    method: "PUT",
    body: payload,
  })
  return data.policy
}

export async function getBreachSummary(orgId: string): Promise<BreachSummary> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ summary: BreachSummary }>(`${BASE}/sla/breach-summary?${qs}`)
  return data.summary
}

export async function triggerRecompute(orgId: string): Promise<{ ok: boolean; updated: number }> {
  const qs = new URLSearchParams({ org_id: orgId })
  return apiClient<{ ok: boolean; updated: number }>(`${BASE}/sla/recompute?${qs}`, {
    method: "POST",
  })
}

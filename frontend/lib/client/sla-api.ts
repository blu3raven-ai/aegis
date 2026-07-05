/** Client for SLA breach stats (per-severity open vs breached counts). */

import { apiClient } from "./api-client.ts"

export interface SlaPolicy {
  severity: "critical" | "high" | "medium" | "low"
  deadline_days: number
  enabled: boolean
}

export interface UpdateSlaPolicyPayload {
  deadline_days: number
  enabled: boolean
}

export async function listSlaPolicies(): Promise<SlaPolicy[]> {
  const data = await apiClient<{ policies: SlaPolicy[] }>("/api/v1/sla/policies")
  return data.policies
}

export async function updateSlaPolicy(severity: string, payload: UpdateSlaPolicyPayload): Promise<SlaPolicy> {
  return apiClient<SlaPolicy>(`/api/v1/sla/policies/${encodeURIComponent(severity)}`, {
    method: "PATCH",
    body: payload,
  })
}

export interface SlaSeverityBreach {
  open: number
  breached: number
  breached_pct: number
}

export interface SlaBreachSummary {
  critical: SlaSeverityBreach
  high: SlaSeverityBreach
  medium: SlaSeverityBreach
  low: SlaSeverityBreach
}

/** Per-severity open/breached counts scoped to the caller's assets. */
export async function getSlaBreachSummary(): Promise<SlaBreachSummary> {
  const data = await apiClient<{ summary: SlaBreachSummary }>("/api/v1/sla/breach-summary")
  return data.summary
}

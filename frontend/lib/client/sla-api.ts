/** Client for SLA breach stats (per-severity open vs breached counts). */

import { apiClient } from "./api-client.ts"

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

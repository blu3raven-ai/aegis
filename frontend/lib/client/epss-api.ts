/**
 * TypeScript client for the EPSS scores REST API (Phase 50).
 *
 * Mirrors the pattern used in sla-api.ts and notification-rules-api.ts.
 * EPSS values are FIRST.org Exploit Prediction Scoring System probabilities
 * in [0.0, 1.0] — both `score` (probability) and `percentile` (ranking).
 */

import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

const BASE = "/api/v1"

export interface EpssScore {
  cve: string
  score: number
  percentile: number
  scored_date: string | null
  fetched_at: string | null
}

export interface EpssTopFinding {
  finding_id: number
  tool: string
  repo: string
  severity: string
  identity_key: string
  cve: string
  epss_score: number
  epss_percentile: number
  scored_date: string | null
}

export interface EpssTopResponse {
  findings: EpssTopFinding[]
  count: number
}

export interface EpssRefreshResult {
  fetched: number
  new: number
}

export class EpssApiError extends Error {
  readonly status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = "EpssApiError"
    this.status = status
  }
}

export async function getEpssScore(cve: string): Promise<EpssScore | null> {
  try {
    return await apiClient<EpssScore>(`${BASE}/epss/scores/${encodeURIComponent(cve)}`)
  } catch (err) {
    if (err instanceof ApiClientError && err.status === 404) return null
    throw err
  }
}

export async function getEpssTop(orgId: string, limit = 5): Promise<EpssTopResponse> {
  const qs = new URLSearchParams({ org_id: orgId, limit: String(limit) })
  return apiClient<EpssTopResponse>(`${BASE}/epss/top?${qs}`)
}

export async function triggerEpssRefresh(): Promise<EpssRefreshResult> {
  return apiClient<EpssRefreshResult>(`${BASE}/epss/refresh`, { method: "POST" })
}

/**
 * Format an EPSS percentile (0.0–1.0) as a rounded whole-number percent.
 * Returns null for non-finite / missing values so callers can render an em dash.
 */
export function formatPercentile(percentile: number | null | undefined): string | null {
  if (percentile == null || !Number.isFinite(percentile)) return null
  return `${Math.round(percentile * 100)}%`
}

/** EPSS percentile severity bucket — drives the dot color in EpssScoreCell. */
export type EpssBucket = "high" | "medium" | "none"

export function epssBucket(percentile: number | null | undefined): EpssBucket {
  if (percentile == null || !Number.isFinite(percentile)) return "none"
  if (percentile >= 0.9) return "high"
  if (percentile >= 0.7) return "medium"
  return "none"
}

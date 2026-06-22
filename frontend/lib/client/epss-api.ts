/** Display helpers for EPSS percentiles (formatting and severity bucketing). */

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

/**
 * Client for the enrichment admin surface (advisory-mirror lifecycle).
 *
 * Backs the settings "Advisory Data" card: read feed freshness/size and trigger
 * an on-demand OSV mirror refresh. All endpoints are MANAGE_SETTINGS-gated.
 */
import { apiClient } from "./api-client.ts"

export interface FeedStatus {
  /** ISO timestamp of the last successful refresh, or null if never refreshed. */
  lastRefreshedAt: string | null
}

export interface EnrichmentStatus {
  osv: FeedStatus & {
    advisories: number
    /** ISO start of the most recent run (may be in-flight — no finishedAt yet). */
    startedAt: string | null
    /** Error from the most recent run, or null on success. */
    error: string | null
  }
  epss: FeedStatus & { scores: number }
  kev: FeedStatus & { entries: number }
}

export async function getEnrichmentStatus(): Promise<EnrichmentStatus> {
  return apiClient<EnrichmentStatus>("/api/v1/enrichment/status")
}

/** Dispatch an OSV catalog refresh. Returns immediately (202) — the refresh runs
 *  in the background; poll {@link getEnrichmentStatus} to observe completion. */
export async function refreshOsvMirror(): Promise<void> {
  await apiClient("/api/v1/enrichment/osv/refresh", { method: "POST" })
}

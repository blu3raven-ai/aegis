/**
 * TypeScript client for the runner fleet REST API (Phase 40).
 *
 * Reads /api/v1/fleet/runners which proxies to the FastAPI backend.
 * Mirrors the pattern used in repos-api.ts.
 */

export interface RunnerStatus {
  agent_id: string
  hostname: string
  scanner_types: string[]
  in_flight_jobs: number
  processed_total: number
  last_heartbeat_at: string
  seconds_since_heartbeat: number
  status: "healthy" | "degraded" | "dead"
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`fleet-api: ${res.status} ${res.statusText} — ${text}`)
  }
  return res.json() as Promise<T>
}

export async function listRunners(): Promise<RunnerStatus[]> {
  const data = await fetchJson<{ runners: RunnerStatus[] }>("/api/v1/fleet/runners")
  return data.runners ?? []
}

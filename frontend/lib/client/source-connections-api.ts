import type {
  CategoryCounts,
  ConnectionMethod,
  ConnectionTestResult,
  ScannerType,
  SourceCategory,
  SourceConnection,
} from "@/lib/shared/sources-types"
import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

// ─── Internal Helpers ─────────────────────────────────────────────────────────

const SOURCES_API_BASE = "/api/v1/sources"

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: string }

function isNetworkFailure(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  const message = error.message.toLowerCase()
  return message.includes("failed to fetch") || message.includes("networkerror")
}

function friendlySourcesUnavailableMessage(): string {
  return "Sources backend is unavailable. Start the backend and try again."
}

async function sourcesRequest<T>(
  path: string,
  init?: { method?: string; body?: unknown },
): Promise<ApiResult<T>> {
  try {
    const data = await apiClient<T>(`${SOURCES_API_BASE}${path}`, {
      method: init?.method,
      body: init?.body,
      cache: "no-store",
    })
    return { ok: true, data }
  } catch (error) {
    if (error instanceof ApiClientError) {
      // Surface the backend's own error message when available so users see
      // "Organisation 'foo' not found" instead of a bare "Request failed (404)".
      const body = error.body as { error?: string; message?: string; detail?: string } | null
      const backendMsg = body?.error ?? body?.message ?? body?.detail
      return { ok: false, error: backendMsg ?? `Request failed (${error.status}).` }
    }
    if (isNetworkFailure(error)) {
      return { ok: false, error: friendlySourcesUnavailableMessage() }
    }
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Request failed.",
    }
  }
}

// ─── REST helpers ─────────────────────────────────────────────────────────────

interface RestSourceAuth {
  orgOrOwner: string | null
  username: string | null
  instanceUrl: string | null
  groupOrProject: string | null
  // Server-masked token ("********" + last 4) — surfaced so the UI can show a
  // last-4 hint identifying which credential is configured. Never the raw token.
  token: string | null
}

interface RestSourceConnection {
  id: string
  sourceType: string
  category: string
  name: string
  status: string
  auth: RestSourceAuth
  scanScope: string
  excludedItems: string[]
  scanners: string[] | null
  connectionMethods: string[] | null
  syncSchedule: string | null
  syncScheduleMode: string | null
  syncScheduleCron: string | null
  scanAutoEnabled: boolean | null
  scanScheduleMode: string | null
  scanSchedulePreset: string | null
  scanScheduleCron: string | null
  statusMessage: string | null
  lastSyncedAt: string | null
  nextSyncAt: string | null
  discoveredItemCount: number | null
  discoveredItems: string[]
  scopeRefs?: string[]
  createdAt: string | null
  updatedAt: string | null
}

function restConnectionToTs(c: RestSourceConnection): SourceConnection {
  return {
    id: c.id,
    category: c.category as SourceConnection["category"],
    sourceType: c.sourceType as SourceConnection["sourceType"],
    name: c.name,
    auth: {
      ...(c.auth.orgOrOwner ? { orgOrOwner: c.auth.orgOrOwner } : {}),
      ...(c.auth.username ? { username: c.auth.username } : {}),
      ...(c.auth.instanceUrl ? { instanceUrl: c.auth.instanceUrl } : {}),
      ...(c.auth.groupOrProject ? { groupOrProject: c.auth.groupOrProject } : {}),
      ...(c.auth.token ? { token: c.auth.token } : {}),
    },
    scanScope: c.scanScope as SourceConnection["scanScope"],
    excludedItems: c.excludedItems,
    scanners: (c.scanners ?? []) as ScannerType[],
    connectionMethods: (c.connectionMethods ?? ["pat"]) as ConnectionMethod[],
    syncSchedule: (c.syncSchedule ?? "6h") as SourceConnection["syncSchedule"],
    syncScheduleMode: (c.syncScheduleMode ?? "preset") as SourceConnection["syncScheduleMode"],
    ...(c.syncScheduleCron ? { syncScheduleCron: c.syncScheduleCron } : {}),
    scanAutoEnabled: c.scanAutoEnabled ?? false,
    scanScheduleMode: (c.scanScheduleMode ?? "preset") as SourceConnection["scanScheduleMode"],
    scanSchedulePreset: (c.scanSchedulePreset ?? "24h") as SourceConnection["scanSchedulePreset"],
    ...(c.scanScheduleCron ? { scanScheduleCron: c.scanScheduleCron } : {}),
    status: c.status as SourceConnection["status"],
    ...(c.statusMessage ? { statusMessage: c.statusMessage } : {}),
    ...(c.lastSyncedAt ? { lastSyncedAt: c.lastSyncedAt } : {}),
    ...(c.nextSyncAt ? { nextSyncAt: c.nextSyncAt } : {}),
    ...(c.discoveredItemCount != null ? { discoveredItemCount: c.discoveredItemCount } : {}),
    ...(c.discoveredItems.length ? { discoveredItems: c.discoveredItems } : {}),
    ...(c.scopeRefs?.length ? { scopeRefs: c.scopeRefs } : {}),
    createdAt: c.createdAt ?? "",
    updatedAt: c.updatedAt ?? "",
  }
}

// ─── Exported API Functions ───────────────────────────────────────────────────

export async function listSourceConnections(
  category?: SourceCategory,
): Promise<ApiResult<{ connections: SourceConnection[] }>> {
  const path = category
    ? `/connections?category=${encodeURIComponent(category)}`
    : "/connections"
  const result = await sourcesRequest<{ connections: RestSourceConnection[] }>(path)
  if (!result.ok) return result
  return {
    ok: true,
    data: { connections: (result.data.connections ?? []).map(restConnectionToTs) },
  }
}

export async function getSourceConnectionCounts(): Promise<
  ApiResult<{ counts: CategoryCounts }>
> {
  const result = await sourcesRequest<{
    counts: { category: string; count: number }[]
  }>("/connections/counts")
  if (!result.ok) return result
  const counts: CategoryCounts = {
    "code-repositories": 0,
    "container-registry": 0,
    "cloud-infrastructure": 0,
    "ci-systems": 0,
  }
  for (const row of result.data.counts ?? []) {
    if (row.category in counts) {
      counts[row.category as keyof CategoryCounts] = row.count
    }
  }
  return { ok: true, data: { counts } }
}

// Create/test input: the schedule-config fields are server-defaulted on create,
// so callers (the connect-source wizard) don't have to supply them.
export type NewConnectionInput = Omit<
  SourceConnection,
  | "id" | "createdAt" | "updatedAt"
  | "syncScheduleMode" | "syncScheduleCron"
  | "scanAutoEnabled" | "scanScheduleMode" | "scanSchedulePreset" | "scanScheduleCron"
  // Scanner selection is configured post-create in source settings; the
  // server defaults a new connection to all scanners for its category.
  | "scanners"
>

export async function createSourceConnection(
  data: NewConnectionInput,
): Promise<ApiResult<{ connection: SourceConnection }>> {
  return sourcesRequest<{ connection: SourceConnection }>("/connections", {
    method: "POST",
    body: data,
  })
}

export async function getSourceConnection(
  id: string,
): Promise<ApiResult<{ connection: SourceConnection }>> {
  const result = await sourcesRequest<{ connection: RestSourceConnection }>(
    `/connections/${encodeURIComponent(id)}`,
  )
  if (!result.ok) return result
  return { ok: true, data: { connection: restConnectionToTs(result.data.connection) } }
}

export async function updateSourceConnection(
  id: string,
  data: Partial<Omit<SourceConnection, "id" | "createdAt" | "updatedAt">>,
): Promise<ApiResult<{ connection: SourceConnection }>> {
  return sourcesRequest<{ connection: SourceConnection }>(
    `/connections/${encodeURIComponent(id)}`,
    {
      method: "PUT",
      body: data,
    },
  )
}

export async function deleteSourceConnection(
  id: string,
): Promise<ApiResult<{ ok: boolean }>> {
  return sourcesRequest<{ ok: boolean }>(
    `/connections/${encodeURIComponent(id)}`,
    { method: "DELETE" },
  )
}

export async function testSourceConnection(
  id: string,
): Promise<ApiResult<ConnectionTestResult>> {
  return sourcesRequest<ConnectionTestResult>(
    `/connections/${encodeURIComponent(id)}/test`,
    { method: "POST" },
  )
}

export async function syncSourceConnection(
  id: string,
): Promise<ApiResult<ConnectionTestResult>> {
  return sourcesRequest<ConnectionTestResult>(
    `/connections/${encodeURIComponent(id)}/sync`,
    { method: "POST" },
  )
}

export async function scanSourceConnection(
  id: string,
): Promise<ApiResult<{ queued: string[]; count: number }>> {
  return sourcesRequest<{ queued: string[]; count: number }>(
    `/connections/${encodeURIComponent(id)}/scan`,
    { method: "POST" },
  )
}

export interface ActiveScanRunProgress {
  percent?: number
  scannedRepos?: number
  finishedRepos?: number
  expectedRepos?: number | null
  currentRepo?: string | null
  stage?: string
}

export type ActiveScanRun = {
  runId: string
  status: string
  /** Persisted progress snapshot, so a banner restored after a refresh can
   *  rehydrate real elapsed/percent state instead of resetting to blank. */
  progress: ActiveScanRunProgress | null
  startedAt: string | null
  createdAt: string | null
  logTail: string[]
}

export async function getActiveSourceScanRuns(
  id: string,
): Promise<ApiResult<{ runs: ActiveScanRun[]; runIds: string[] }>> {
  return sourcesRequest<{ runs: ActiveScanRun[]; runIds: string[] }>(
    `/connections/${encodeURIComponent(id)}/scan/active`,
  )
}

/** One entry per connection that currently has an active source scan. */
export type ActiveScanSummary = { connectionId: string; org: string; runIds: string[] }

/**
 * All in-flight source scans (manual or scheduled) across connections, so the
 * global banner can discover scans not started from the current page.
 */
export async function getAllActiveSourceScans(): Promise<
  ApiResult<{ scans: ActiveScanSummary[] }>
> {
  return sourcesRequest<{ scans: ActiveScanSummary[] }>(`/scans/active`)
}

export async function cancelSourceScan(
  id: string,
  runIds: string[],
): Promise<ApiResult<{ cancelled: string[] }>> {
  return sourcesRequest<{ cancelled: string[] }>(
    `/connections/${encodeURIComponent(id)}/scan/cancel`,
    { method: "POST", body: { run_ids: runIds } },
  )
}

export async function testNewSourceConnection(
  data: NewConnectionInput,
): Promise<ApiResult<ConnectionTestResult>> {
  return sourcesRequest<ConnectionTestResult>("/connections/test-new", {
    method: "POST",
    body: data,
  })
}

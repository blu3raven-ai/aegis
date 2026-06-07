import type {
  CategoryCounts,
  ConnectionTestResult,
  SourceCategory,
  SourceConnection,
} from "@/lib/shared/sources-types"
import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

// ─── Internal Helpers ─────────────────────────────────────────────────────────

const SETTINGS_API_BASE = "/api/settings"

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
    const data = await apiClient<T>(`${SETTINGS_API_BASE}${path}`, {
      method: init?.method,
      body: init?.body,
      cache: "no-store",
    })
    return { ok: true, data }
  } catch (error) {
    if (error instanceof ApiClientError) {
      return { ok: false, error: `Request failed (${error.status}).` }
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

// ─── Exported API Functions ───────────────────────────────────────────────────

export async function listSourceConnections(
  category?: SourceCategory,
): Promise<ApiResult<{ connections: SourceConnection[] }>> {
  const query = category ? `?category=${encodeURIComponent(category)}` : ""
  return sourcesRequest<{ connections: SourceConnection[] }>(
    `/sources${query}`,
  )
}

export async function getSourceConnectionCounts(): Promise<
  ApiResult<{ counts: CategoryCounts }>
> {
  return sourcesRequest<{ counts: CategoryCounts }>("/sources/counts")
}

export async function createSourceConnection(
  data: Omit<SourceConnection, "id" | "createdAt" | "updatedAt">,
): Promise<ApiResult<{ connection: SourceConnection }>> {
  return sourcesRequest<{ connection: SourceConnection }>("/sources", {
    method: "POST",
    body: data,
  })
}

export async function getSourceConnection(
  id: string,
): Promise<ApiResult<{ connection: SourceConnection }>> {
  return sourcesRequest<{ connection: SourceConnection }>(
    `/sources/${encodeURIComponent(id)}`,
  )
}

export async function updateSourceConnection(
  id: string,
  data: Partial<Omit<SourceConnection, "id" | "createdAt" | "updatedAt">>,
): Promise<ApiResult<{ connection: SourceConnection }>> {
  return sourcesRequest<{ connection: SourceConnection }>(
    `/sources/${encodeURIComponent(id)}`,
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
    `/sources/${encodeURIComponent(id)}`,
    { method: "DELETE" },
  )
}

export async function testSourceConnection(
  id: string,
): Promise<ApiResult<ConnectionTestResult>> {
  return sourcesRequest<ConnectionTestResult>(
    `/sources/${encodeURIComponent(id)}/test`,
    { method: "POST" },
  )
}

export async function syncSourceConnection(
  id: string,
): Promise<ApiResult<ConnectionTestResult>> {
  return sourcesRequest<ConnectionTestResult>(
    `/sources/${encodeURIComponent(id)}/sync`,
    { method: "POST" },
  )
}

export async function testNewSourceConnection(
  data: Omit<SourceConnection, "id" | "createdAt" | "updatedAt">,
): Promise<ApiResult<ConnectionTestResult>> {
  return sourcesRequest<ConnectionTestResult>("/sources/test-new", {
    method: "POST",
    body: data,
  })
}

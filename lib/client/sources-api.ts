import type {
  CategoryCounts,
  ConnectionTestResult,
  SourceCategory,
  SourceConnection,
} from "@/lib/shared/sources-types"

// ─── Internal Helpers ─────────────────────────────────────────────────────────

const SETTINGS_API_BASE = "/api/settings"

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: string }

type ApiErrorPayload = {
  error?: unknown
  detail?: unknown
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text()
  if (!text) return null

  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

function getErrorMessage(payload: unknown, fallback: string): string {
  if (typeof payload === "string" && payload.trim()) return payload
  if (payload && typeof payload === "object") {
    const { error, detail } = payload as ApiErrorPayload
    if (typeof error === "string" && error.trim()) return error
    if (typeof detail === "string" && detail.trim()) return detail
  }
  return fallback
}

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
  init?: RequestInit,
): Promise<ApiResult<T>> {
  try {
    const response = await fetch(`${SETTINGS_API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
      cache: "no-store",
    })

    const payload = await readJson(response)

    if (!response.ok) {
      return {
        ok: false,
        error: getErrorMessage(payload, `Request failed (${response.status}).`),
      }
    }

    return { ok: true, data: payload as T }
  } catch (error) {
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
    body: JSON.stringify(data),
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
      body: JSON.stringify(data),
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
    body: JSON.stringify(data),
  })
}

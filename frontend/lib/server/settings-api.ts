import { getJson } from "@/lib/server/internal-api"
import type { AppConfig } from "@/lib/server/app-config"
import type { GetSettingsResult, RoleRecord } from "@/lib/shared/settings-types"

export type { GetSettingsResult, RoleRecord }

interface PrerequisitesResponse {
  runner_connected: boolean
  scanner_status: string
  error?: string
}

export async function checkToolPrerequisites(
  tool: string,
  user: { id: string; role: string; roleId?: string | null },
): Promise<{ ready: boolean }> {
  try {
    const data = await getJson<PrerequisitesResponse>(
      `/api/v1/settings/tools/${tool}/prerequisites`, user
    )
    return { ready: data.runner_connected && data.scanner_status === "ready" }
  } catch {
    // If backend is unreachable, assume ready — don't block user on settings tab
    // because of a transient network issue. They'll see empty data but can navigate freely.
    return { ready: true }
  }
}

function formatSettingsError(error: unknown, fallback = "Could not load settings.") {
  if (isNetworkFailure(error)) {
    return "Settings backend is unavailable. Start the backend and try again."
  }
  if (error instanceof Error) {
    return error.message || fallback
  }
  return fallback
}

function isNetworkFailure(error: unknown) {
  if (!(error instanceof Error)) return false
  const message = error.message.toLowerCase()
  return message.includes("failed to fetch") || message.includes("networkerror")
}

export async function getSettingsServer(user: { id: string; role: string; roleId?: string | null }): Promise<GetSettingsResult> {
  try {
    const data = await getJson<AppConfig>("/api/v1/settings", user)
    return { ok: true, data }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function getUserCountServer(user: { id: string; role: string; roleId?: string | null }): Promise<number | undefined> {
  try {
    const data = await getJson<{ users: any[] }>("/api/v1/settings/users", user)
    return Array.isArray(data.users) ? data.users.length : undefined
  } catch {
    return undefined
  }
}

export async function getTeamCountServer(user: { id: string; role: string; roleId?: string | null }): Promise<number | undefined> {
  try {
    const data = await getJson<{ teams?: unknown[] }>("/api/v1/settings/organisations", user)
    return Array.isArray(data.teams) ? data.teams.length : undefined
  } catch {
    return undefined
  }
}

export async function getRoleCountServer(user: { id: string; role: string; roleId?: string | null }): Promise<number | undefined> {
  try {
    const data = await getJson<{ roles?: unknown[] }>("/api/v1/settings/roles", user)
    return Array.isArray(data.roles) ? data.roles.length : undefined
  } catch {
    return undefined
  }
}


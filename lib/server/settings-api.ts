import { getJson } from "@/lib/server/internal-api"
import type { AppConfig } from "@/lib/server/app-config"
import type { GetSettingsResult, RoleRecord } from "@/lib/shared/settings-types"
import { createLogger } from "@/lib/server/logger"

const log = createLogger("settings")

export type { GetSettingsResult, RoleRecord }

interface PrerequisitesResponse {
  docker_image_present: boolean
  signature_valid: boolean
  scanner_status: string
  error?: string
}

export async function checkToolPrerequisites(
  tool: string,
  user: { id: string; role: string; roleId?: string | null },
): Promise<{ ready: boolean }> {
  try {
    const data = await getJson<PrerequisitesResponse>(
      `/settings/api/tools/${tool}/prerequisites`, user
    )
    return { ready: data.docker_image_present && (data.scanner_status === "verified" || data.scanner_status === "ready") }
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
    const data = await getJson<AppConfig>("/settings/api", user)
    return { ok: true, data }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function getUserCountServer(user: { id: string; role: string; roleId?: string | null }): Promise<number | undefined> {
  try {
    const data = await getJson<{ users: any[] }>("/settings/api/users", user)
    return Array.isArray(data.users) ? data.users.length : undefined
  } catch {
    return undefined
  }
}

export async function getTeamCountServer(user: { id: string; role: string; roleId?: string | null }): Promise<number | undefined> {
  try {
    const data = await getJson<{ teams?: unknown[] }>("/settings/api/organisations", user)
    return Array.isArray(data.teams) ? data.teams.length : undefined
  } catch {
    return undefined
  }
}

export async function getRoleCountServer(user: { id: string; role: string; roleId?: string | null }): Promise<number | undefined> {
  try {
    const data = await getJson<{ roles?: unknown[] }>("/settings/api/roles", user)
    return Array.isArray(data.roles) ? data.roles.length : undefined
  } catch {
    return undefined
  }
}

export async function fetchPolicyServer(user: { id: string; role: string; roleId?: string | null }): Promise<RoleRecord | null> {
  try {
    if (user.roleId) {
      const data = await getJson<{ role: RoleRecord }>(
        `/settings/api/roles/${encodeURIComponent(user.roleId)}`,
        user,
      )
      return data.role
    }

    const data = await getJson<any>("/settings/api/policy", user)
    return {
      id: "legacy",
      name: "Legacy",
      slug: user.role,
      description: "",
      permissions: data[user.role] || [],
      isSystem: true,
      isLocked: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
  } catch (error) {
    log.error("Failed to fetch policy:", error)
    return null
  }
}

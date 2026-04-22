import type { AppConfig } from "@/lib/server/app-config"
import type {
  GetSettingsResult,
  SaveSettingsResult,
  ScannerPrerequisitesResult,
  OrganisationTeam,
  ResourceSharingIndex,
  UserDirectoryEntry,
  RoleRecord,
  RoleInput,
  DirectGrant,
  GitHubSyncPreview,
} from "@/lib/shared/settings-types"

export type {
  GetSettingsResult,
  SaveSettingsResult,
  ScannerPrerequisitesResult,
  OrganisationTeam,
  ResourceSharingIndex,
  UserDirectoryEntry,
  RoleRecord,
  RoleInput,
  DirectGrant,
  GitHubSyncPreview,
}

type ToolKey = "dependencies" | "codeScanning" | "secrets" | "iacSecurity" | "containerScanning"

type JsonRecord = Record<string, unknown>

type ApiErrorPayload = {
  error?: unknown
  detail?: unknown
}

const SETTINGS_API_BASE = "/api/settings"

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text()
  if (!text) return null

  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

function getErrorMessage(payload: unknown, fallback: string) {
  if (typeof payload === "string" && payload.trim()) return payload
  if (payload && typeof payload === "object") {
    const { error, detail } = payload as ApiErrorPayload
    if (typeof error === "string" && error.trim()) return error
    if (typeof detail === "string" && detail.trim()) return detail
  }
  return fallback
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
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
    throw new Error(getErrorMessage(payload, `Request failed (${response.status}).`))
  }

  return payload as T
}

async function requestResult(path: string, init: RequestInit): Promise<SaveSettingsResult> {
  try {
    await requestJson<JsonRecord>(path, init)
    return { ok: true }
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Request failed.",
    }
  }
}

function extractErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback
}

function isNetworkFailure(error: unknown) {
  if (!(error instanceof Error)) return false
  const message = error.message.toLowerCase()
  return message.includes("failed to fetch") || message.includes("networkerror")
}

function friendlySettingsUnavailableMessage() {
  return "Settings backend is unavailable. Start the backend and try again."
}

export function formatSettingsError(error: unknown, fallback = "Could not load settings.") {
  if (isNetworkFailure(error)) {
    return friendlySettingsUnavailableMessage()
  }
  if (error instanceof Error) {
    return error.message || fallback
  }
  return fallback
}

export async function checkScannerPrerequisites(tool: string): Promise<ScannerPrerequisitesResult> {
  try {
    const data = await requestJson<{
      docker_image_present: boolean
      image_name: string
      registry_image: string
      signature: string | null
      signature_valid: boolean
      digest: string | null
      error: string | null
      scanner_status: string | null
      scanner_source: string | null
      runner_name: string | null
      runner_platform: string | null
    }>(`/tools/${tool}/prerequisites`)
    return {
      ok: true,
      dockerImagePresent: data.docker_image_present,
      imageName: data.image_name,
      registryImage: data.registry_image,
      signature: data.signature,
      signatureValid: data.signature_valid,
      digest: data.digest,
      error: data.error,
      scanner_status: data.scanner_status,
      scanner_source: data.scanner_source,
      runner_name: data.runner_name,
      runner_platform: data.runner_platform,
    }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function getSettings(): Promise<GetSettingsResult> {
  try {
    const data = await requestJson<AppConfig>("")
    return { ok: true, data }
  } catch (error) {
    return {
      ok: false,
      error: formatSettingsError(error),
    }
  }
}

export async function savePolicy(policy: {
  admin: string[]
  security: string[]
  viewer: string[]
}): Promise<SaveSettingsResult> {
  try {
    const response = await fetch("/api/settings/policy", {
      method: "PATCH",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(policy),
      cache: "no-store",
    })
    const payload = await readJson(response)
    if (!response.ok) {
      return { ok: false, error: getErrorMessage(payload, "Policy update failed.") }
    }
    return { ok: true }
  } catch (error) {
    if (isNetworkFailure(error)) {
      return { ok: false, error: friendlySettingsUnavailableMessage() }
    }
    return { ok: false, error: extractErrorMessage(error, "Policy update failed.") }
  }
}

export async function saveGeneralSettings(input: {
  username: string
  currentPassword?: string
  newPassword?: string
  confirmNewPassword?: string
}): Promise<SaveSettingsResult> {
  const username = input.username.trim()

  const result = await requestResult("/general", {
    method: "PATCH",
    body: JSON.stringify({ orgs: [], username }),
  })

  if (!result.ok) {
    if (result.error.toLowerCase().includes("failed to fetch")) {
      return { ok: false, error: friendlySettingsUnavailableMessage() }
    }
    return result
  }

  const hasPasswordChange =
    Boolean(input.currentPassword || input.newPassword || input.confirmNewPassword)

  if (!hasPasswordChange) {
    return { ok: true }
  }

  return saveAccountSettings({
    username,
    currentPassword: input.currentPassword,
    newPassword: input.newPassword,
    confirmNewPassword: input.confirmNewPassword,
  })
}

export async function saveAccountSettings(input: {
  username: string
  currentPassword?: string
  newPassword?: string
  confirmNewPassword?: string
}): Promise<SaveSettingsResult> {
  try {
    const response = await fetch("/api/account", {
      method: "PATCH",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: input.username,
        current_password: input.currentPassword,
        new_password: input.newPassword,
        confirm_new_password: input.confirmNewPassword,
      }),
      cache: "no-store",
    })
    const payload = await readJson(response)
    if (!response.ok) {
      return { ok: false, error: getErrorMessage(payload, "Account update failed.") }
    }
    return { ok: true }
  } catch (error) {
    if (isNetworkFailure(error)) {
      return { ok: false, error: friendlySettingsUnavailableMessage() }
    }
    return { ok: false, error: extractErrorMessage(error, "Account update failed.") }
  }
}

export async function saveToolSettings(input: {
  tool: ToolKey
  enabled: boolean
  settings: Record<string, string>
}): Promise<SaveSettingsResult> {
  const result = await requestResult(`/tools/${input.tool}`, {
    method: "PATCH",
    body: JSON.stringify({
      enabled: input.enabled,
      settings: input.settings,
    }),
  })

  if (!result.ok && result.error.toLowerCase().includes("failed to fetch")) {
    return { ok: false, error: friendlySettingsUnavailableMessage() }
  }
  return result
}

function normalizeRoleRecord(role: Omit<RoleRecord, "slug"> & { slug?: string }): RoleRecord {
  const fallbackSlug = role.id.startsWith("role_") ? role.id.slice(5) : "custom"
  return {
    ...role,
    slug: role.slug ?? fallbackSlug,
  }
}

export async function listRoles(): Promise<{ ok: true; roles: RoleRecord[] } | { ok: false; error: string }> {
  try {
    const data = await requestJson<{ roles: RoleRecord[] }>("/roles")
    return { ok: true, roles: data.roles.map(normalizeRoleRecord) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function getRole(roleId: string): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  try {
    const data = await requestJson<{ role: RoleRecord }>(`/roles/${encodeURIComponent(roleId)}`)
    return { ok: true, role: normalizeRoleRecord(data.role) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function createRole(input: RoleInput): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  try {
    const data = await requestJson<{ role: RoleRecord }>("/roles", {
      method: "POST",
      body: JSON.stringify(input),
    })
    return { ok: true, role: normalizeRoleRecord(data.role) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function updateRole(roleId: string, input: RoleInput): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  try {
    const data = await requestJson<{ role: RoleRecord }>(`/roles/${encodeURIComponent(roleId)}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    })
    return { ok: true, role: normalizeRoleRecord(data.role) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function duplicateRole(roleId: string): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  try {
    const data = await requestJson<{ role: RoleRecord }>(`/roles/${encodeURIComponent(roleId)}/duplicate`, {
      method: "POST",
    })
    return { ok: true, role: data.role }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function deleteRole(roleId: string, replacementRoleId?: string): Promise<SaveSettingsResult> {
  try {
    await requestJson(`/roles/${encodeURIComponent(roleId)}`, {
      method: "DELETE",
      body: JSON.stringify({ replacementRoleId }),
    })
    return { ok: true }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

type OrganisationTeamMutationResult =
  | { ok: true; team: OrganisationTeam; sharing: ResourceSharingIndex }
  | { ok: false; error: string }

async function requestOrganisationTeamMutation(
  path: string,
  init: RequestInit,
): Promise<OrganisationTeamMutationResult> {
  try {
    const data = await requestJson<{ team: OrganisationTeam; sharing?: ResourceSharingIndex }>(path, init)
    return {
      ok: true,
      team: data.team,
      sharing: data.sharing ?? { repositories: {}, containerImages: {} },
    }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function listOrganisationTeams(): Promise<
  { ok: true; teams: OrganisationTeam[]; sharing: ResourceSharingIndex } | { ok: false; error: string }
> {
  try {
    const data = await requestJson<{ teams: OrganisationTeam[]; sharing?: ResourceSharingIndex }>("/organisations")
    return {
      ok: true,
      teams: Array.isArray(data.teams) ? data.teams : [],
      sharing: data.sharing ?? { repositories: {}, containerImages: {} },
    }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function listUserDirectory(): Promise<
  { ok: true; users: UserDirectoryEntry[] } | { ok: false; error: string }
> {
  try {
    const data = await requestJson<{ users: UserDirectoryEntry[] }>("/users/directory")
    return { ok: true, users: Array.isArray(data.users) ? data.users : [] }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function createOrganisationTeam(input: { name: string; description: string }): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation("/organisations", {
    method: "POST",
    body: JSON.stringify(input),
  })
}

export async function updateOrganisationTeam(teamId: string, input: { name: string; description: string }): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation(`/organisations/${encodeURIComponent(teamId)}`, {
    method: "PATCH",
    body: JSON.stringify(input),
  })
}

export async function deleteOrganisationTeam(teamId: string) {
  return requestResult(`/organisations/${encodeURIComponent(teamId)}`, { method: "DELETE" })
}

export async function addOrganisationTeamMember(
  teamId: string,
  input: { userId: string },
): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation(`/organisations/${encodeURIComponent(teamId)}/members`, {
    method: "POST",
    body: JSON.stringify(input),
  })
}

export async function removeOrganisationTeamMember(
  teamId: string,
  userId: string,
): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation(
    `/organisations/${encodeURIComponent(teamId)}/members/${encodeURIComponent(userId)}`,
    { method: "DELETE" },
  )
}

export async function addOrganisationRepository(teamId: string, repository: string): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation(`/organisations/${encodeURIComponent(teamId)}/repositories`, {
    method: "POST",
    body: JSON.stringify({ repository }),
  })
}

export async function removeOrganisationRepository(
  teamId: string,
  org: string,
  repo: string,
): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation(
    `/organisations/${encodeURIComponent(teamId)}/repositories/${encodeURIComponent(org)}/${encodeURIComponent(repo)}`,
    { method: "DELETE" },
  )
}

export async function addOrganisationContainerImage(teamId: string, image: string): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation(`/organisations/${encodeURIComponent(teamId)}/container-images`, {
    method: "POST",
    body: JSON.stringify({ image }),
  })
}

export async function removeOrganisationContainerImage(
  teamId: string,
  image: string,
): Promise<OrganisationTeamMutationResult> {
  return requestOrganisationTeamMutation(
    `/organisations/${encodeURIComponent(teamId)}/container-images?image=${encodeURIComponent(image)}`,
    { method: "DELETE" },
  )
}

export async function listDirectGrants(): Promise<{ ok: true; grants: DirectGrant[] } | { ok: false; error: string }> {
  try {
    const data = await requestJson<{ grants: DirectGrant[] }>("/direct-grants")
    return { ok: true, grants: Array.isArray(data.grants) ? data.grants : [] }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function addDirectGrant(
  userId: string,
  resourceType: "repository" | "containerImage",
  resourceKey: string,
): Promise<SaveSettingsResult> {
  return requestResult("/direct-grants", {
    method: "POST",
    body: JSON.stringify({ userId, resourceType, resourceKey }),
  })
}

export async function removeDirectGrant(
  userId: string,
  resourceType: string,
  resourceKey: string,
): Promise<SaveSettingsResult> {
  return requestResult(
    `/direct-grants/${encodeURIComponent(userId)}/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceKey)}`,
    { method: "DELETE" },
  )
}

export async function searchOrganisationRepositories(
  org: string | null,
  q: string,
): Promise<{ repositories: Array<{ org: string; repo: string; fullName: string }>; error?: string }> {
  try {
    const orgParam = org ? `org=${encodeURIComponent(org)}&` : ""
    return await requestJson<{ repositories: Array<{ org: string; repo: string; fullName: string }>; error?: string }>(
      `/resources/repositories?${orgParam}q=${encodeURIComponent(q)}`,
    )
  } catch (error) {
    return { repositories: [], error: formatSettingsError(error) }
  }
}

export async function searchOrganisationContainerImages(
  org: string | null,
  q: string,
): Promise<{ images: Array<{ image: string; name: string }>; error?: string }> {
  try {
    const orgParam = org ? `org=${encodeURIComponent(org)}&` : ""
    return await requestJson<{ images: Array<{ image: string; name: string }>; error?: string }>(
      `/resources/container-images?${orgParam}q=${encodeURIComponent(q)}`,
    )
  } catch (error) {
    return { images: [], error: formatSettingsError(error) }
  }
}

export async function previewGitHubSync(): Promise<
  { ok: true; preview: GitHubSyncPreview } | { ok: false; error: string }
> {
  try {
    const data = await requestJson<{ preview: GitHubSyncPreview }>("/github-sync/preview", {
      method: "POST",
    })
    return { ok: true, preview: data.preview }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function applyGitHubSync(): Promise<
  { ok: true; result: GitHubSyncPreview } | { ok: false; error: string }
> {
  try {
    const data = await requestJson<{ result: GitHubSyncPreview }>("/github-sync/apply", {
      method: "POST",
    })
    return { ok: true, result: data.result }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function saveAuthSecuritySettings(input: {
  requireMfaManualUsers: boolean
  requireMfaAdmins: boolean
  trustedSessionDurationDays: number
  recoveryCodePolicy: "mandatory" | "optional" | "disabled"
}): Promise<SaveSettingsResult> {
  return requestResult("/auth-security", {
    method: "PATCH",
    body: JSON.stringify(input),
  })
}

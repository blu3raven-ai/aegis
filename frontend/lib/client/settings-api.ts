import type { AppConfig } from "@/lib/server/app-config"
import type {
  GetSettingsResult,
  SaveSettingsResult,
  OrganisationTeam,
  ResourceSharingIndex,
  UserDirectoryEntry,
  RoleRecord,
  RoleInput,
  Grant,
  DirectGrant,
} from "@/lib/shared/settings-types"
import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"
import { gqlQuery } from "./graphql-client.ts"

export type {
  GetSettingsResult,
  SaveSettingsResult,
  OrganisationTeam,
  ResourceSharingIndex,
  UserDirectoryEntry,
  RoleRecord,
  RoleInput,
  Grant,
  DirectGrant,
}

type ToolKey = "dependencies_scanning" | "code_scanning" | "secret_scanning" | "iac_scanning" | "container_scanning"

type JsonRecord = Record<string, unknown>

type ApiErrorPayload = {
  error?: unknown
  detail?: unknown
}

const SETTINGS_API_BASE = "/api/v1/settings"

function getErrorMessage(payload: unknown, fallback: string) {
  if (typeof payload === "string" && payload.trim()) return payload
  if (payload && typeof payload === "object") {
    const { error, detail } = payload as ApiErrorPayload
    if (typeof error === "string" && error.trim()) return error
    if (typeof detail === "string" && detail.trim()) return detail
  }
  return fallback
}

async function requestJsonAbsolute<T>(url: string, init?: RequestInit): Promise<T> {
  try {
    return await apiClient<T>(url, {
      method: init?.method,
      body: init?.body ? JSON.parse(init.body as string) : undefined,
      headers: init?.headers as Record<string, string> | undefined,
    })
  } catch (err) {
    if (err instanceof ApiClientError) {
      throw new Error(getErrorMessage(err.body, `Request failed (${err.status}).`))
    }
    throw err
  }
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  return requestJsonAbsolute<T>(`${SETTINGS_API_BASE}${path}`, init)
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
    await apiClient("/api/v1/settings/account", {
      method: "PATCH",
      body: {
        username: input.username,
        current_password: input.currentPassword,
        new_password: input.newPassword,
        confirm_new_password: input.confirmNewPassword,
      },
    })
    return { ok: true }
  } catch (error) {
    if (error instanceof ApiClientError) {
      return { ok: false, error: getErrorMessage(error.body, "Account update failed.") }
    }
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

export type AdvisoryKeyTestResult =
  | { ok: true; valid: boolean; error: string }
  | { ok: false; error: string }

/** Validate an advisory-source key (NVD or GHSA) against its upstream without
 *  persisting it, so the modal can show an immediate valid/invalid result. */
export async function testAdvisoryKey(source: "nvd" | "ghsa", apiKey: string): Promise<AdvisoryKeyTestResult> {
  try {
    const data = await requestJson<{ valid: boolean; error: string }>("/advisory-key/test", {
      method: "POST",
      body: JSON.stringify({ source, apiKey }),
    })
    return { ok: true, valid: Boolean(data.valid), error: data.error ?? "" }
  } catch (error) {
    return {
      ok: false,
      error: isNetworkFailure(error) ? friendlySettingsUnavailableMessage() : extractErrorMessage(error, "Test failed."),
    }
  }
}

export type ScannerPrerequisitesResult =
  | { ok: true; runner_connected: boolean; error: string | null; scanner_status?: string | null; runner_name?: string | null; runner_platform?: string | null }
  | { ok: false; error: string }

export async function checkScannerPrerequisites(tool: ToolKey): Promise<ScannerPrerequisitesResult> {
  try {
    const data = await requestJson<Record<string, unknown>>(`/tools/${tool}/prerequisites`)
    return {
      ok: true,
      runner_connected: data.runner_connected as boolean,
      error: (data.error as string) ?? null,
      scanner_status: (data.scanner_status as string) ?? null,
      runner_name: (data.runner_name as string) ?? null,
      runner_platform: (data.runner_platform as string) ?? null,
    }
  } catch (error) {
    return { ok: false, error: extractErrorMessage(error, "Could not check prerequisites.") }
  }
}

// ---------------------------------------------------------------------------
// Workspace — GraphQL
// ---------------------------------------------------------------------------

type GqlTeamMember = { userId: string; source: string }
type GqlTeamAsset = {
  assetId: string
  type: string
  displayName: string
  externalRef: string
  source: string
}
type GqlTeam = {
  id: string
  name: string
  description: string
  source: string
  members: GqlTeamMember[]
  assets: GqlTeamAsset[]
  isShared: boolean
  createdAt: string
  updatedAt: string
}
type GqlRole = {
  id: string
  name: string
  description: string
  permissions: string[]
  isSystem: boolean
  isLocked: boolean
  createdAt: string
  updatedAt: string
}
type GqlGrant = {
  subjectType: string
  subjectId: string
  assetId: string
  assetType: string
  assetDisplayName: string
  assetExternalRef: string
  source: string
  createdAt: string
}

const TEAM_FIELDS = `
  id name description source
  members { userId source }
  assets { assetId type displayName externalRef source }
  isShared createdAt updatedAt
`

function gqlTeamToOrganisationTeam(t: GqlTeam): OrganisationTeam {
  return {
    id: t.id,
    name: t.name,
    description: t.description,
    source: t.source as "manual" | "github",
    members: t.members.map((m) => ({ userId: m.userId, source: m.source as "manual" | "github" })),
    assets: t.assets.map((a) => ({
      assetId: a.assetId,
      type: a.type as "repo" | "image",
      displayName: a.displayName,
      externalRef: a.externalRef,
      source: a.source as "manual" | "github",
    })),
    isShared: t.isShared,
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  }
}

function gqlGrantToGrant(g: GqlGrant): Grant {
  return {
    subjectType: g.subjectType as "user" | "team",
    subjectId: g.subjectId,
    assetId: g.assetId,
    source: g.source,
    createdAt: g.createdAt,
    assetType: g.assetType || undefined,
    assetDisplayName: g.assetDisplayName || undefined,
    assetExternalRef: g.assetExternalRef || undefined,
  }
}

function normalizeRoleRecord(role: Omit<RoleRecord, "slug"> & { slug?: string }): RoleRecord {
  const fallbackSlug = role.id.startsWith("role_") ? role.id.slice(5) : "custom"
  return {
    ...role,
    slug: role.slug ?? fallbackSlug,
  }
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

export async function listRoles(): Promise<{ ok: true; roles: RoleRecord[] } | { ok: false; error: string }> {
  try {
    const data = await apiClient<{ roles: GqlRole[] }>("/api/v1/workspace/roles")
    return { ok: true, roles: data.roles.map(normalizeRoleRecord) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function getRole(roleId: string): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  try {
    const data = await apiClient<{ role: GqlRole }>(
      `/api/v1/workspace/roles/${encodeURIComponent(roleId)}`,
    )
    return { ok: true, role: normalizeRoleRecord(data.role) }
  } catch (error) {
    if (error instanceof ApiClientError && error.status === 404) {
      return { ok: false, error: "Role not found." }
    }
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function createRole(input: RoleInput): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  try {
    const data = await apiClient<{ role: GqlRole }>("/api/v1/workspace/roles", {
      method: "POST",
      body: {
        name: input.name,
        description: input.description,
        permissions: input.permissions,
      },
    })
    return { ok: true, role: normalizeRoleRecord(data.role) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function updateRole(
  roleId: string,
  input: RoleInput,
): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  try {
    const data = await apiClient<{ role: GqlRole }>(
      `/api/v1/workspace/roles/${encodeURIComponent(roleId)}`,
      {
        method: "PATCH",
        body: {
          name: input.name,
          description: input.description,
          permissions: input.permissions,
        },
      },
    )
    return { ok: true, role: normalizeRoleRecord(data.role) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function duplicateRole(source: RoleRecord): Promise<{ ok: true; role: RoleRecord } | { ok: false; error: string }> {
  return createRole({
    name: `${source.name} Copy`,
    description: source.description,
    permissions: source.permissions,
  })
}

export async function deleteRole(roleId: string, replacementRoleId?: string): Promise<SaveSettingsResult> {
  try {
    const qs = replacementRoleId
      ? `?replacement_role_id=${encodeURIComponent(replacementRoleId)}`
      : ""
    await apiClient(
      `/api/v1/workspace/roles/${encodeURIComponent(roleId)}${qs}`,
      { method: "DELETE" },
    )
    return { ok: true }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

// ---------------------------------------------------------------------------
// Teams
// ---------------------------------------------------------------------------

export async function listOrganisationTeams(): Promise<
  { ok: true; teams: OrganisationTeam[] } | { ok: false; error: string }
> {
  try {
    const data = await gqlQuery<{ workspace: { teams: GqlTeam[] } }>(`
      query WorkspaceTeams { workspace { teams { ${TEAM_FIELDS} } } }
    `)
    const teams = data.workspace?.teams
    return {
      ok: true,
      teams: Array.isArray(teams) ? teams.map(gqlTeamToOrganisationTeam) : [],
    }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function listUserDirectory(): Promise<
  { ok: true; users: UserDirectoryEntry[] } | { ok: false; error: string }
> {
  try {
    const data = await gqlQuery<{ workspace: { userDirectory: UserDirectoryEntry[] } }>(`
      query WorkspaceUserDirectory { workspace { userDirectory { id username email role status } } }
    `)
    const users = data.workspace?.userDirectory
    return { ok: true, users: Array.isArray(users) ? users : [] }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function createOrganisationTeam(
  input: { name: string; description: string },
): Promise<{ ok: true; team: OrganisationTeam } | { ok: false; error: string }> {
  try {
    const data = await apiClient<GqlTeam>("/api/v1/workspace/teams", {
      method: "POST",
      body: { name: input.name, description: input.description },
    })
    return { ok: true, team: gqlTeamToOrganisationTeam(data) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function updateOrganisationTeam(
  teamId: string,
  input: { name: string; description: string },
): Promise<{ ok: true; team: OrganisationTeam } | { ok: false; error: string }> {
  try {
    const data = await apiClient<GqlTeam>(`/api/v1/workspace/teams/${teamId}`, {
      method: "PATCH",
      body: { name: input.name, description: input.description },
    })
    return { ok: true, team: gqlTeamToOrganisationTeam(data) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function deleteOrganisationTeam(teamId: string): Promise<SaveSettingsResult> {
  try {
    await apiClient(`/api/v1/workspace/teams/${teamId}`, { method: "DELETE" })
    return { ok: true }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function addOrganisationTeamMember(
  teamId: string,
  input: { userId: string },
): Promise<{ ok: true; team: OrganisationTeam } | { ok: false; error: string }> {
  try {
    const data = await apiClient<GqlTeam>(`/api/v1/workspace/teams/${teamId}/members`, {
      method: "POST",
      body: { userId: input.userId },
    })
    return { ok: true, team: gqlTeamToOrganisationTeam(data) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function removeOrganisationTeamMember(
  teamId: string,
  userId: string,
): Promise<{ ok: true; team: OrganisationTeam } | { ok: false; error: string }> {
  try {
    const data = await apiClient<GqlTeam>(`/api/v1/workspace/teams/${teamId}/members/${userId}`, {
      method: "DELETE",
    })
    return { ok: true, team: gqlTeamToOrganisationTeam(data) }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

// ---------------------------------------------------------------------------
// Asset grants
// ---------------------------------------------------------------------------

export async function attachAssetToTeam(teamId: string, assetId: string): Promise<SaveSettingsResult> {
  try {
    await apiClient("/api/v1/workspace/grants", {
      method: "POST",
      body: { subject_type: "team", subject_id: teamId, asset_id: assetId },
    })
    return { ok: true }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function detachAssetFromTeam(teamId: string, assetId: string): Promise<SaveSettingsResult> {
  try {
    await apiClient("/api/v1/workspace/grants", {
      method: "DELETE",
      body: { subject_type: "team", subject_id: teamId, asset_id: assetId },
    })
    return { ok: true }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function addOrganisationRepository(teamId: string, repository: string): Promise<SaveSettingsResult> {
  const trimmed = repository.trim()
  const slash = trimmed.indexOf("/")
  if (slash <= 0 || slash === trimmed.length - 1) {
    return { ok: false, error: "Repository must use org/repo format." }
  }
  const owner = trimmed.slice(0, slash)
  const name = trimmed.slice(slash + 1)
  let assetId: string
  try {
    const created = await requestJsonAbsolute<{ asset_id: string }>("/api/v1/sources/manual", {
      method: "POST",
      body: JSON.stringify({ type: "repo", source_type: "github", owner, name }),
    })
    assetId = created.asset_id
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
  return attachAssetToTeam(teamId, assetId)
}

export async function removeOrganisationRepository(teamId: string, assetId: string): Promise<SaveSettingsResult> {
  return detachAssetFromTeam(teamId, assetId)
}

export async function addOrganisationContainerImage(teamId: string, image: string): Promise<SaveSettingsResult> {
  const trimmed = image.trim()
  const parts = trimmed.split("/")
  if (parts.length < 3 || parts.some((p) => !p)) {
    return { ok: false, error: "Container image must use registry/org/image format." }
  }
  const [registry, ...rest] = parts
  let assetId: string
  try {
    const created = await requestJsonAbsolute<{ asset_id: string }>("/api/v1/sources/manual", {
      method: "POST",
      body: JSON.stringify({ type: "image", registry, image: rest.join("/"), tag: "" }),
    })
    assetId = created.asset_id
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
  return attachAssetToTeam(teamId, assetId)
}

export async function removeOrganisationContainerImage(teamId: string, assetId: string): Promise<SaveSettingsResult> {
  return detachAssetFromTeam(teamId, assetId)
}

// ---------------------------------------------------------------------------
// Direct user grants
// ---------------------------------------------------------------------------

export async function listDirectGrants(): Promise<{ ok: true; grants: Grant[] } | { ok: false; error: string }> {
  try {
    const data = await apiClient<{ grants: GqlGrant[] }>(
      "/api/v1/workspace/grants?subject_type=user",
    )
    return { ok: true, grants: Array.isArray(data.grants) ? data.grants.map(gqlGrantToGrant) : [] }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function addDirectGrant(userId: string, assetId: string): Promise<SaveSettingsResult> {
  try {
    await apiClient("/api/v1/workspace/grants", {
      method: "POST",
      body: { subject_type: "user", subject_id: userId, asset_id: assetId },
    })
    return { ok: true }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

export async function removeDirectGrant(userId: string, assetId: string): Promise<SaveSettingsResult> {
  try {
    await apiClient("/api/v1/workspace/grants", {
      method: "DELETE",
      body: { subject_type: "user", subject_id: userId, asset_id: assetId },
    })
    return { ok: true }
  } catch (error) {
    return { ok: false, error: formatSettingsError(error) }
  }
}

// ---------------------------------------------------------------------------
// Source searches (REST)
// ---------------------------------------------------------------------------

export async function searchOrganisationRepositories(
  org: string | null,
  q: string,
): Promise<{ repositories: Array<{ org: string; repo: string; fullName: string }>; error?: string }> {
  try {
    const orgParam = org ? `org=${encodeURIComponent(org)}&` : ""
    return await requestJsonAbsolute<{ repositories: Array<{ org: string; repo: string; fullName: string }>; error?: string }>(
      `/api/v1/sources/repos/search?${orgParam}q=${encodeURIComponent(q)}`,
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
    return await requestJsonAbsolute<{ images: Array<{ image: string; name: string }>; error?: string }>(
      `/api/v1/sources/images/search?${orgParam}q=${encodeURIComponent(q)}`,
    )
  } catch (error) {
    return { images: [], error: formatSettingsError(error) }
  }
}


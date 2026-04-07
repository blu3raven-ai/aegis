import type { UserRole } from "@/lib/shared/auth/roles"
import type { AppConfig } from "@/lib/server/app-config"

export type GetSettingsResult =
  | { ok: true; data: AppConfig }
  | { ok: false; error: string }

export type SaveSettingsResult =
  | { ok: true }
  | { ok: false; error: string }

/** Single source of truth for all scanner prerequisite responses. */
export type ScannerPrerequisitesResult =
  | {
      ok: true
      dockerImagePresent: boolean
      imageName: string
      registryImage: string
      signature: string | null
      signatureValid: boolean
      digest: string | null
      error: string | null
      scanner_status: string | null
      scanner_source: string | null
      runner_name: string | null
      runner_platform: string | null
    }
  | { ok: false; error: string }

export interface OrganisationTeam {
  id: string
  name: string
  description: string
  source: "manual" | "github"
  members: Array<{ userId: string; source: "manual" | "github" }>
  repositories: Array<{ org: string; repo: string; source: "manual" | "github" }>
  containerImages: Array<{ image: string }>
  createdAt: string
  updatedAt: string
  lastSyncedAt?: string
}

export interface ResourceSharingIndex {
  repositories: Record<string, string[]>
  containerImages: Record<string, string[]>
}

export interface UserDirectoryEntry {
  id: string
  username: string
  email?: string
  role: UserRole
  status: "active" | "disabled" | "pending"
}

export interface RoleRecord {
  id: string
  slug: string
  name: string
  description: string
  permissions: string[]
  isSystem: boolean
  isLocked: boolean
  createdAt: string
  updatedAt: string
}

export interface RoleInput {
  id?: string
  name: string
  description: string
  permissions: string[]
}

export interface DirectGrant {
  userId: string
  resourceType: "repository" | "containerImage"
  resourceKey: string
  source: "github-direct" | "manual-direct"
  createdAt: string
}

export interface GitHubSyncPreview {
  teamsToCreate: unknown[]
  teamsToUpdate: unknown[]
  membersToAdd: unknown[]
  membersToRemove: unknown[]
  usersToCreateAsViewer: unknown[]
  pendingUsersToActivate: unknown[]
  repositoriesToAdd: unknown[]
  repositoriesToRemove: unknown[]
  containerImagesToAdd: unknown[]
  containerImagesToRemove: unknown[]
  directGrantsToAdd: unknown[]
  directGrantsToRemove: unknown[]
  preservedManualMembers: unknown[]
  preservedRolePromotions: unknown[]
}

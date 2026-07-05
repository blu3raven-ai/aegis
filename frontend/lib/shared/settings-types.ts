import type { UserRole } from "@/lib/shared/auth/roles"
import type { AppConfig } from "@/lib/server/app-config"

export type GetSettingsResult =
  | { ok: true; data: AppConfig }
  | { ok: false; error: string }

export type SaveSettingsResult =
  | { ok: true }
  | { ok: false; error: string }

export interface TeamAsset {
  assetId: string
  type: "repo" | "image"
  displayName: string
  externalRef: string
  source: "manual" | "github"
}

export interface OrganisationTeam {
  id: string
  name: string
  description: string
  source: "manual" | "github"
  members: Array<{ userId: string; source: "manual" | "github" }>
  assets: TeamAsset[]
  isShared?: boolean
  createdAt: string
  updatedAt: string
  lastSyncedAt?: string
}

/** assetId → list of teamIds that own it. Computed client-side from the teams list. */
export type ResourceSharingIndex = Record<string, string[]>

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

export interface Grant {
  subjectType: "user" | "team"
  subjectId: string
  assetId: string
  source: string
  createdAt: string
  assetType?: string
  assetDisplayName?: string
  assetExternalRef?: string
}

/** @deprecated Use Grant */
export type DirectGrant = Grant


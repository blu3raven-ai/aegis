import type { UserRole } from "@/lib/shared/auth/roles"

export type TeamRole = "admin" | "security" | "viewer"
export type TeamSource = "manual" | "github"
export type MembershipSource = "manual" | "github"

export interface TeamMember {
  userId: string
  source?: "manual" | "github"
}

export interface TeamAsset {
  assetId: string
  type: "repo" | "image"
  displayName: string
  externalRef: string
  source: MembershipSource
}

export interface OrganisationTeam {
  id: string
  name: string
  description: string
  source?: TeamSource
  members: TeamMember[]
  assets: TeamAsset[]
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
  status: "active" | "disabled"
}

export const TEAM_ROLE_ORDER: TeamRole[] = ["admin", "security", "viewer"]

export const TEAM_ROLE_LABELS: Record<TeamRole, string> = {
  admin: "Team Admin",
  security: "Security Reviewer",
  viewer: "Team Viewer",
}

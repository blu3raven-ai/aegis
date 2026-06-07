import type { UserRole } from "@/lib/shared/auth/roles"

export type TeamRole = "admin" | "security" | "viewer"
export type TeamSource = "manual" | "github"
export type MembershipSource = "manual" | "github"

export interface TeamMember {
  userId: string
  source?: "manual" | "github"
}

export interface TeamRepository {
  org: string
  repo: string
  source?: MembershipSource
}

export interface TeamContainerImage {
  image: string
}

export interface OrganisationTeam {
  id: string
  name: string
  description: string
  source?: TeamSource
  members: TeamMember[]
  repositories: TeamRepository[]
  containerImages: TeamContainerImage[]
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
  status: "active" | "disabled"
}

export const TEAM_ROLE_ORDER: TeamRole[] = ["admin", "security", "viewer"]

export const TEAM_ROLE_LABELS: Record<TeamRole, string> = {
  admin: "Team Admin",
  security: "Security Reviewer",
  viewer: "Team Viewer",
}

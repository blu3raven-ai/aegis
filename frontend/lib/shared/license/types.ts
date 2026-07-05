export type Tier = "community" | "enterprise"

export interface TierLimits {
  max_users: number | null
  max_remote_runners: number | null
  max_source_connections: number | null
  custom_roles: boolean
  teams: boolean
  insights_tab: boolean
  health_tab: boolean
  ai_review: boolean
  custom_scan_schedule: boolean
  sso: boolean
  audit_log: boolean
  data_retention_days: number | null
}

export interface LicenseUsage {
  users: number
  source_connections: number
  teams: number
  custom_roles: number
  remote_runners: number
}

export interface LicenseStatus {
  tier: Tier
  addons: string[]
  limits: TierLimits
  usage: LicenseUsage
  license: {
    org: string
    expiresAt: string
    licenseId: string
  } | null
}

export const TIER_ORDER: Record<Tier, number> = {
  community: 0,
  enterprise: 1,
}

export const TIER_LABELS: Record<Tier, string> = {
  community: "Community",
  enterprise: "Enterprise",
}

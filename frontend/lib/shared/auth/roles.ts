import { IMPLIED_PERMISSIONS } from "@/lib/shared/auth/permissions"
import type { Permission } from "@/lib/shared/auth/permissions"
export type { Permission } from "@/lib/shared/auth/permissions"
export { PERMISSION_GROUPS, IMPLIED_PERMISSIONS } from "@/lib/shared/auth/permissions"

export type UserRole = "owner" | "admin" | "security" | "viewer"

export const ROLE_LABELS: Record<UserRole, string> = {
  owner: "Owner",
  admin: "Admin",
  security: "Security",
  viewer: "Viewer",
}

const ROLE_PERMISSIONS: Record<UserRole, Set<Permission>> = {
  owner: new Set([
    "view_dashboards",
    "view_findings",
    "review_findings",
    "export_findings",
    "run_scans",
    "cancel_scans",
    "view_scan_history",
    "view_reports",
    "export_reports",
    "view_settings",
    "manage_settings",
    "view_users",
    "manage_users",
    "view_roles",
    "manage_roles",
    "view_access_scope",
    "manage_access_scope",
    "view_sources",
    "manage_sources",
    "view_audit",
    "view_rules",
    "manage_sla_rules",
    "manage_scanner_coverage_rules",
    "manage_auto_dismiss_rules",
    "manage_data_retention_rules",
  ]),
  admin: new Set([
    "view_dashboards",
    "view_findings",
    "review_findings",
    "run_scans",
    "refresh_dashboard",
    "view_settings",
    "manage_settings",
    "manage_users",
    "manage_organisations",
    "view_audit",
    "view_rules",
  ]),
  security: new Set([
    "view_dashboards",
    "view_findings",
    "review_findings",
    "run_scans",
    "refresh_dashboard",
    "view_settings",
    "view_rules",
  ]),
  viewer: new Set(["view_dashboards", "view_findings"]),
}

export function resolveEffectivePermissions(permissions: string[]): Set<Permission> {
  const effective = new Set<Permission>(permissions as Permission[])
  for (const [parent, children] of Object.entries(IMPLIED_PERMISSIONS)) {
    if (effective.has(parent as Permission)) {
      for (const child of children) {
        effective.add(child)
      }
    }
  }
  return effective
}

export function can(
  role: UserRole,
  permission: Permission,
  policy?: Record<string, string[]> | { permissions: string[] }
): boolean {
  if (role === "owner") return true
  
  if (policy) {
    if ("permissions" in policy) {
      // New format: individual role record
      return resolveEffectivePermissions(policy.permissions).has(permission)
    }
    if (policy[role]) {
      // Legacy format: policy board mapping
      return policy[role].includes(permission)
    }
  }

  return ROLE_PERMISSIONS[role]?.has(permission) ?? false
}


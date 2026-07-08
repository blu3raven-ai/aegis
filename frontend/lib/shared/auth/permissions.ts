export type Permission =
  | "view_dashboards"
  | "view_findings"
  | "review_findings"
  | "export_findings"
  | "run_scans"
  | "cancel_scans"
  | "view_scan_history"
  | "view_reports"
  | "export_reports"
  | "view_settings"
  | "manage_settings"
  | "manage_runners"
  | "view_users"
  | "manage_users"
  | "view_roles"
  | "manage_roles"
  | "view_access_scope"
  | "manage_access_scope"
  | "view_audit"
  | "manage_organisations"
  | "refresh_dashboard"
  | "view_sources"
  | "manage_sources"
  | "view_rules"
  | "manage_sla_rules"
  | "manage_scanner_coverage_rules"
  | "manage_auto_dismiss_rules"
  | "manage_data_retention_rules"

export interface PermissionDefinition {
  id: Permission
  label: string
  description: string
}

export interface PermissionGroup {
  id: string
  label: string
  permissions: PermissionDefinition[]
}

export const PERMISSION_GROUPS: PermissionGroup[] = [
  {
    id: "general",
    label: "General",
    permissions: [
      { id: "view_dashboards", label: "View Dashboards", description: "Access to main overview and stats." },
      { id: "refresh_dashboard", label: "Refresh Dashboard", description: "Trigger dashboard data refresh." },
      { id: "view_audit", label: "View Audit Logs", description: "View system activity and audit trail." },
    ],
  },
  {
    id: "findings",
    label: "Findings",
    permissions: [
      { id: "view_findings", label: "View Findings", description: "View SCA and Secrets security alerts." },
      { id: "review_findings", label: "Review Findings", description: "Acknowledge or dismiss findings." },
      { id: "export_findings", label: "Export Findings", description: "Download finding data in various formats." },
    ],
  },
  {
    id: "scans",
    label: "Scans",
    permissions: [
      { id: "run_scans", label: "Run Scans", description: "Trigger new scans for organizations." },
      { id: "cancel_scans", label: "Cancel Scans", description: "Stop currently running scan jobs." },
      { id: "view_scan_history", label: "View Scan History", description: "View details of previous scan runs." },
    ],
  },
  {
    id: "reports",
    label: "Reports",
    permissions: [
      { id: "view_reports", label: "View Reports", description: "Access to security and compliance reports." },
      { id: "export_reports", label: "Export Reports", description: "Download generated PDF or CSV reports." },
    ],
  },
  {
    id: "users",
    label: "Users",
    permissions: [
      { id: "view_users", label: "View Users", description: "View workspace member list." },
      { id: "manage_users", label: "Manage Users", description: "Add/remove users and change assignments." },
    ],
  },
  {
    id: "roles",
    label: "Roles",
    permissions: [
      { id: "view_roles", label: "View Roles", description: "View role definitions and permission summaries." },
      { id: "manage_roles", label: "Manage Roles", description: "Create, edit, duplicate, and delete custom roles." },
    ],
  },
  {
    id: "access",
    label: "Access Scope",
    permissions: [
      { id: "view_access_scope", label: "View Access Scope", description: "View teams, direct grants, and access sources." },
      { id: "manage_access_scope", label: "Manage Access Scope", description: "Manage teams, memberships, resources, and manual direct grants." },
      { id: "manage_organisations", label: "Manage Organisations", description: "Manage organization-level settings (legacy alias)." },
    ],
  },
  {
    id: "sources",
    label: "Sources",
    permissions: [
      { id: "view_sources", label: "View Sources", description: "View configured source connections." },
      { id: "manage_sources", label: "Manage Sources", description: "Add, edit, and remove source connections." },
    ],
  },
  {
    id: "settings",
    label: "Settings",
    permissions: [
      { id: "view_settings", label: "View Settings", description: "Access the settings pages." },
      { id: "manage_settings", label: "Manage Settings", description: "Change global and tool configuration." },
      { id: "manage_runners", label: "Manage Runners", description: "Configure, approve, and revoke self-hosted scan runners." },
    ],
  },
  {
    id: "rules",
    label: "Policies",
    permissions: [
      { id: "view_rules", label: "View Rules", description: "View rules across all categories." },
      { id: "manage_sla_rules", label: "Manage SLA Rules", description: "Create, edit, and delete SLA rules." },
      { id: "manage_scanner_coverage_rules", label: "Manage Scanner Coverage Rules", description: "Create, edit, and delete scanner coverage rules." },
      { id: "manage_auto_dismiss_rules", label: "Manage Auto-Dismiss Rules", description: "Create, edit, and delete auto-dismiss rules." },
      { id: "manage_data_retention_rules", label: "Manage Data Retention Rules", description: "Create, edit, and delete data retention rules." },
    ],
  },
]

export const IMPLIED_PERMISSIONS: Partial<Record<Permission, Permission[]>> = {
  manage_settings: ["view_settings", "manage_runners"],
  manage_users: ["view_users"],
  manage_roles: ["view_roles"],
  manage_access_scope: ["view_access_scope"],
  manage_sources: ["view_sources"],
  export_findings: ["view_findings"],
  export_reports: ["view_reports"],
  manage_sla_rules: ["view_rules"],
  manage_scanner_coverage_rules: ["view_rules"],
  manage_auto_dismiss_rules: ["view_rules"],
  manage_data_retention_rules: ["view_rules"],
}

// ── Field schema types ────────────────────────────────────────────────────────

export interface ConditionFieldSchema {
  /** Field key sent to the backend */
  value: string
  /** Display label shown in the UI */
  label: string
  /** Optional autocomplete values (e.g. severity options) */
  valueSuggestions?: string[]
  /** UI rendering hint for the value input */
  inputType?: "text" | "number" | "boolean" | "select"
}

// ── Canonical field lists ─────────────────────────────────────────────────────

// Only fields carried by the finding.created event payload can be matched at
// routing time. Repository, CVE, label, and chain-role conditions require
// payload enrichment that isn't in place yet, so they are omitted rather than
// offered as conditions that would silently never match.
export const NOTIFICATION_ROUTING_FIELDS: ConditionFieldSchema[] = [
  { value: "severity", label: "Severity", inputType: "select", valueSuggestions: ["critical", "high", "medium", "low", "info"] },
  { value: "scanner", label: "Scanner", inputType: "select", valueSuggestions: ["dependencies_scanning", "code_scanning", "secret_scanning", "container_scanning", "iac_scanning"] },
]

export const SLA_RULE_FIELDS: ConditionFieldSchema[] = [
  { value: "severity", label: "Severity", inputType: "select", valueSuggestions: ["critical", "high", "medium", "low", "info"] },
  { value: "scanner", label: "Scanner", inputType: "select", valueSuggestions: ["dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning", "iac_scanning"] },
  { value: "kev_matched", label: "KEV-matched", inputType: "boolean" },
  { value: "cve_id", label: "CVE ID", inputType: "text" },
  { value: "cwe_id", label: "CWE ID", inputType: "text" },
  { value: "repo_id", label: "Repository ID", inputType: "text" },
  { value: "repo_labels", label: "Repo labels", inputType: "text" },
  { value: "file_path", label: "File path", inputType: "text" },
  { value: "age_days", label: "Age (days)", inputType: "number" },
]

export const SCANNER_COVERAGE_RULE_FIELDS: ConditionFieldSchema[] = [
  { value: "tier", label: "Repo tier", inputType: "select", valueSuggestions: ["production", "staging", "development"] },
  { value: "repo_labels", label: "Repo labels", inputType: "text" },
  { value: "archived", label: "Archived", inputType: "boolean" },
  { value: "image_registry", label: "Image registry", inputType: "text" },
  { value: "last_scan_age_days", label: "Last scan age (days)", inputType: "number" },
]

export const AUTO_DISMISS_RULE_FIELDS: ConditionFieldSchema[] = [
  { value: "severity", label: "Severity", inputType: "select", valueSuggestions: ["critical", "high", "medium", "low", "info"] },
  { value: "scanner", label: "Scanner", inputType: "select", valueSuggestions: ["dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning", "iac_scanning"] },
  { value: "dependency_scope", label: "Dependency scope", inputType: "select", valueSuggestions: ["dev", "prod"] },
  { value: "release_age_days", label: "Release age (days)", inputType: "number" },
  { value: "file_path", label: "File path", inputType: "text" },
  { value: "cwe_id", label: "CWE ID", inputType: "text" },
  { value: "cve_id", label: "CVE ID", inputType: "text" },
  { value: "repo_id", label: "Repository ID", inputType: "text" },
  { value: "repo_labels", label: "Repo labels", inputType: "text" },
  { value: "repo_archived", label: "Repo archived", inputType: "boolean" },
]

export const DATA_RETENTION_RULE_FIELDS: ConditionFieldSchema[] = [
  { value: "tool", label: "Scanner", inputType: "select", valueSuggestions: ["dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning", "iac_scanning"] },
  { value: "repo_id", label: "Repository ID", inputType: "text" },
  { value: "age_days", label: "Scan age (days)", inputType: "number" },
]

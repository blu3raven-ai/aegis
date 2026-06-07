/**
 * TypeScript client for the rules REST API.
 */

import { ApiClientError } from "./api-client.types.ts"
import { apiClient } from "./api-client.ts"
import type { Condition } from "@/lib/rules-engine/conditions"

export type RuleCategory = "sla" | "scanner_coverage" | "auto_dismiss" | "data_retention"

/** Categories that have a working editor/modal in this phase. */
export type EditableRuleCategory = Extract<
  RuleCategory,
  "sla" | "scanner_coverage" | "auto_dismiss" | "data_retention"
>

export interface SlaEscalation {
  at_hours: number
  channel_id: number
}

export interface SlaAction {
  deadline_days: number
  escalations: SlaEscalation[]
}

export type ScannerType = "dependencies" | "code_scanning" | "container_scanning" | "secrets"

export interface RequireScannersAction {
  type: "require_scanners"
  required_scanners: ScannerType[]
}

export interface StaleAlertAction {
  type: "stale_alert"
  stale_after_days: number
  alert_channel_id: number
  auto_retrigger: boolean
}

export type ScannerCoverageAction = RequireScannersAction | StaleAlertAction

export interface AutoDismissAction {
  /** User-facing dismissal reason, 3-200 chars. */
  reason: string
  /** Internal audit note, 0-500 chars. */
  audit_note?: string | null
  /** Safety net: % threshold (1-100) over the alarm window. */
  rate_alarm_pct: number
  /** Safety net: window length in minutes (5-10080). */
  rate_alarm_window_minutes: number
}

export interface ArchiveAction {
  type: "archive"
  after_days: number
}

export interface DeleteAction {
  type: "delete"
  after_days: number
}

export type DataRetentionAction = ArchiveAction | DeleteAction

export type RuleAction =
  | SlaAction
  | ScannerCoverageAction
  | AutoDismissAction
  | DataRetentionAction
  | Record<string, unknown>

export function isSlaAction(action: RuleAction): action is SlaAction {
  return (
    typeof action === "object" &&
    action !== null &&
    typeof (action as SlaAction).deadline_days === "number" &&
    Array.isArray((action as SlaAction).escalations)
  )
}

export function isRequireScannersAction(action: RuleAction): action is RequireScannersAction {
  return (
    typeof action === "object" &&
    action !== null &&
    (action as RequireScannersAction).type === "require_scanners" &&
    Array.isArray((action as RequireScannersAction).required_scanners)
  )
}

export function isStaleAlertAction(action: RuleAction): action is StaleAlertAction {
  return (
    typeof action === "object" &&
    action !== null &&
    (action as StaleAlertAction).type === "stale_alert" &&
    typeof (action as StaleAlertAction).stale_after_days === "number" &&
    typeof (action as StaleAlertAction).alert_channel_id === "number"
  )
}

export function isAutoDismissAction(action: RuleAction): action is AutoDismissAction {
  return (
    typeof action === "object" &&
    action !== null &&
    typeof (action as AutoDismissAction).reason === "string" &&
    typeof (action as AutoDismissAction).rate_alarm_pct === "number" &&
    typeof (action as AutoDismissAction).rate_alarm_window_minutes === "number"
  )
}

export function isArchiveAction(action: RuleAction): action is ArchiveAction {
  return (
    typeof action === "object" &&
    action !== null &&
    (action as ArchiveAction).type === "archive" &&
    typeof (action as ArchiveAction).after_days === "number"
  )
}

export function isDeleteAction(action: RuleAction): action is DeleteAction {
  return (
    typeof action === "object" &&
    action !== null &&
    (action as DeleteAction).type === "delete" &&
    typeof (action as DeleteAction).after_days === "number"
  )
}

export function isDataRetentionAction(action: RuleAction): action is DataRetentionAction {
  return isArchiveAction(action) || isDeleteAction(action)
}


export interface RuleSummary {
  id: string
  org_id: string
  category: RuleCategory
  name: string
  description: string | null
  enabled: boolean
  priority: number
  conditions: Condition
  action: RuleAction
  created_by: string
  created_at: string
  updated_at: string | null
  last_evaluated_at: string | null
  violation_count_open: number
  violation_count_resolved_30d: number
}

export interface RuleViolation {
  id: string
  rule_id: string
  subject_type: string
  subject_id: string
  status: "open" | "resolved"
  opened_at: string
  resolved_at: string | null
  context: Record<string, unknown>
}

export interface RuleViolationPage {
  violations: RuleViolation[]
  total: number
  limit: number
  offset: number
}

export interface RuleSummaryStats {
  active_rules: number
  violations_open: number
  coverage_gaps: number
  sla_compliance_pct: number
}

export interface RulePreviewResponse {
  matched_count: number
  rule_id: string
  category: RuleCategory
}

export interface CreateRulePayload {
  org_id: string
  category: RuleCategory
  name: string
  description?: string | null
  enabled?: boolean
  priority?: number
  conditions: Condition
  action: RuleAction
}

export interface UpdateRulePayload {
  name?: string
  description?: string | null
  enabled?: boolean
  priority?: number
  conditions?: Condition
  action?: RuleAction
  dry_run_confirmation_token?: string
}

export interface DryRunSampleMatch {
  finding_id: number
  severity: string
  scanner: string
  repo_id: string
  file_path?: string | null
  cve_id?: string | null
}

export interface DryRunConfirmation {
  token: string
  match_count: number
  sample_matches: DryRunSampleMatch[]
  valid_until: string
}

export interface ListRulesFilters {
  category?: RuleCategory
  enabled?: boolean
  q?: string
}

const BASE = "/api/v1/rules"

export async function listRules(orgId: string, filters?: ListRulesFilters): Promise<RuleSummary[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  if (filters?.category !== undefined) qs.set("category", filters.category)
  if (filters?.enabled !== undefined) qs.set("enabled", String(filters.enabled))
  if (filters?.q !== undefined) qs.set("q", filters.q)
  const data = await apiClient<{ rules: RuleSummary[] }>(`${BASE}?${qs}`)
  return data.rules ?? []
}

export async function getRulesSummary(orgId: string): Promise<RuleSummaryStats> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ summary: RuleSummaryStats }>(`${BASE}/summary?${qs}`)
  return data.summary
}

export async function getRule(orgId: string, ruleId: string): Promise<RuleSummary | null> {
  const qs = new URLSearchParams({ org_id: orgId })
  try {
    const data = await apiClient<{ rule: RuleSummary }>(`${BASE}/${ruleId}?${qs}`)
    return data.rule
  } catch (err) {
    if (err instanceof ApiClientError && err.status === 404) return null
    throw err
  }
}

export async function listRuleViolations(
  orgId: string,
  ruleId: string,
  opts?: { limit?: number; offset?: number },
): Promise<RuleViolationPage> {
  const qs = new URLSearchParams({ org_id: orgId })
  if (opts?.limit !== undefined) qs.set("limit", String(opts.limit))
  if (opts?.offset !== undefined) qs.set("offset", String(opts.offset))
  return apiClient<RuleViolationPage>(`${BASE}/${ruleId}/violations?${qs}`)
}

export async function createRule(payload: CreateRulePayload): Promise<RuleSummary> {
  const data = await apiClient<{ rule: RuleSummary }>(BASE, {
    method: "POST",
    body: payload,
  })
  return data.rule
}

export async function updateRule(
  orgId: string,
  ruleId: string,
  payload: UpdateRulePayload,
): Promise<RuleSummary> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ rule: RuleSummary }>(`${BASE}/${ruleId}?${qs}`, {
    method: "PUT",
    body: payload,
  })
  return data.rule
}

export async function deleteRule(orgId: string, ruleId: string): Promise<void> {
  const qs = new URLSearchParams({ org_id: orgId })
  await apiClient<void>(`${BASE}/${ruleId}?${qs}`, { method: "DELETE" })
}

export async function toggleRule(orgId: string, ruleId: string): Promise<RuleSummary> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ rule: RuleSummary }>(`${BASE}/${ruleId}/toggle?${qs}`, {
    method: "POST",
  })
  return data.rule
}

export async function previewRule(
  orgId: string,
  ruleId: string,
  body?: { sample_subject?: Record<string, unknown> },
): Promise<RulePreviewResponse> {
  const qs = new URLSearchParams({ org_id: orgId })
  return apiClient<RulePreviewResponse>(`${BASE}/${ruleId}/preview?${qs}`, {
    method: "POST",
    body: body ?? {},
  })
}

export async function dryRunAndConfirm(
  orgId: string,
  ruleId: string,
): Promise<DryRunConfirmation> {
  const qs = new URLSearchParams({ org_id: orgId })
  return apiClient<DryRunConfirmation>(
    `${BASE}/${ruleId}/dry-run-and-confirm?${qs}`,
    { method: "POST", body: {} },
  )
}

export interface KillSwitch {
  id: number
  org_id: string
  category: RuleCategory
  killed_at: string
  killed_by: string
  reason: string | null
}

export async function listKillSwitches(orgId: string): Promise<KillSwitch[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ kill_switches: KillSwitch[] }>(
    `${BASE}/kill-switch?${qs}`,
  )
  return data.kill_switches ?? []
}

export async function engageKillSwitch(
  orgId: string,
  category: RuleCategory,
  reason?: string,
): Promise<KillSwitch> {
  const qs = new URLSearchParams({ org_id: orgId })
  return apiClient<KillSwitch>(`${BASE}/kill-switch/${category}?${qs}`, {
    method: "POST",
    body: { reason: reason ?? null },
  })
}

export async function disengageKillSwitch(
  orgId: string,
  category: RuleCategory,
): Promise<void> {
  const qs = new URLSearchParams({ org_id: orgId })
  await apiClient<void>(`${BASE}/kill-switch/${category}?${qs}`, {
    method: "DELETE",
  })
}

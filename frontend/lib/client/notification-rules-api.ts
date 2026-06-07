/**
 * TypeScript client for the notification routing rules REST API (Phase 42).
 *
 * Mirrors the pattern used in destinations-api.ts.
 */

import { apiClient } from "./api-client.ts"
import type { Condition } from "@/lib/rules-engine/conditions"

export type { Condition, ConditionOp, LeafCondition, AllCondition, AnyCondition } from "@/lib/rules-engine/conditions"

/**
 * Whitelist of finding fields used by notification routing rules.
 * Kept separate from LeafCondition.field (which is plain string) so this
 * union can be used for other typed surfaces like PreviewFinding.
 */
export type FindingField =
  | "severity"
  | "scanner"
  | "repo_id"
  | "repo_labels"
  | "cve_id"
  | "chain_role"

export interface NotificationRule {
  id: string
  name: string
  enabled: boolean
  priority: number
  channel_id: number
  conditions: Condition
  org_id: string
  created_at: string
  updated_at: string
}

export type CreateRulePayload = {
  org_id: string
  name: string
  channel_id: number
  conditions: Condition
  priority?: number
  enabled?: boolean
}

export type UpdateRulePayload = {
  name?: string
  enabled?: boolean
  priority?: number
  channel_id?: number
  conditions?: Condition
}

export interface PreviewFinding {
  severity?: string
  scanner?: string
  repo_id?: string
  repo_labels?: string[]
  cve_id?: string | null
  chain_role?: string | null
}

export interface PreviewSingleRuleRequest {
  rule: CreateRulePayload
  finding: PreviewFinding
}

export interface PreviewOrgRequest {
  org_id: string
  finding: PreviewFinding
}

export interface PreviewSingleResult {
  matched: boolean
  channel_id: number | null
  rule_name: string
}

export interface PreviewBreakdownItem {
  rule_id: string
  rule_name: string
  priority: number
  channel_id: number
  matched: boolean
}

export interface PreviewOrgResult {
  matched_channel_ids: number[]
  breakdown: PreviewBreakdownItem[]
}

const BASE = "/api/v1/notification-rules"

export async function listRules(orgId: string): Promise<NotificationRule[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await apiClient<{ rules: NotificationRule[] }>(`${BASE}?${qs}`)
  return data.rules ?? []
}

export async function createRule(payload: CreateRulePayload): Promise<NotificationRule> {
  return apiClient<NotificationRule>(BASE, {
    method: "POST",
    body: payload,
  })
}

export async function updateRule(
  id: string,
  orgId: string,
  payload: UpdateRulePayload,
): Promise<NotificationRule> {
  const qs = new URLSearchParams({ org_id: orgId })
  return apiClient<NotificationRule>(`${BASE}/${id}?${qs}`, {
    method: "PUT",
    body: payload,
  })
}

export async function deleteRule(id: string, orgId: string): Promise<void> {
  const qs = new URLSearchParams({ org_id: orgId })
  await apiClient<void>(`${BASE}/${id}?${qs}`, { method: "DELETE" })
}

export async function previewRule(req: PreviewSingleRuleRequest): Promise<PreviewSingleResult> {
  return apiClient<PreviewSingleResult>(`${BASE}/preview`, {
    method: "POST",
    body: req,
  })
}

export async function previewOrg(req: PreviewOrgRequest): Promise<PreviewOrgResult> {
  return apiClient<PreviewOrgResult>(`${BASE}/preview`, {
    method: "POST",
    body: req,
  })
}

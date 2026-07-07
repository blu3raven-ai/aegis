/** Client for notification-routing rules (read via GraphQL, mutate via REST). */

import { apiClient } from "./api-client.ts"
import { gqlFetch } from "./graphql-fetch.ts"
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
  created_at: string
  updated_at: string
}

export type CreateRulePayload = {
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

const BASE = "/api/v1/notifications/rules"

const NOTIFICATION_RULES_QUERY = `query NotificationRules {
  notifications {
    rules {
      id
      name
      channelId
      conditions
      priority
      enabled
      createdAt
      updatedAt
    }
  }
}`

interface GqlNotificationRule {
  id: string
  name: string
  channelId: number
  conditions: Condition
  priority: number
  enabled: boolean
  createdAt: string
  updatedAt: string
}

interface GqlNotificationRulesResponse {
  notifications: { rules: GqlNotificationRule[] }
}

export async function listRules(): Promise<NotificationRule[]> {
  const data = await gqlFetch<GqlNotificationRulesResponse>(
    "NotificationRules",
    NOTIFICATION_RULES_QUERY,
    {},
  )
  return (data.notifications?.rules ?? []).map((r) => ({
    id: r.id,
    name: r.name,
    channel_id: r.channelId,
    conditions: r.conditions ?? ({} as Condition),
    priority: r.priority,
    enabled: r.enabled,
    created_at: r.createdAt,
    updated_at: r.updatedAt,
  }))
}

export async function createRule(payload: CreateRulePayload): Promise<NotificationRule> {
  return apiClient<NotificationRule>(BASE, {
    method: "POST",
    body: payload,
  })
}

export async function updateRule(
  id: string,
  payload: UpdateRulePayload,
): Promise<NotificationRule> {
  return apiClient<NotificationRule>(`${BASE}/${id}`, {
    method: "PUT",
    body: payload,
  })
}

export async function deleteRule(id: string): Promise<void> {
  await apiClient<void>(`${BASE}/${id}`, { method: "DELETE" })
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
    body: { evaluate_all_active: true, finding: req.finding },
  })
}

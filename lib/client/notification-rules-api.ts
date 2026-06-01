/**
 * TypeScript client for the notification routing rules REST API (Phase 42).
 *
 * Mirrors the pattern used in destinations-api.ts.
 */

export type ConditionOp =
  | "eq"
  | "neq"
  | "in"
  | "nin"
  | "contains"
  | "not_contains"
  | "gt"
  | "gte"
  | "lt"
  | "lte"

export type FindingField =
  | "severity"
  | "scanner"
  | "repo_id"
  | "repo_labels"
  | "cve_id"
  | "chain_role"

export interface LeafCondition {
  field: FindingField
  op: ConditionOp
  value: string | string[]
}

export interface AllCondition {
  all: Condition[]
}

export interface AnyCondition {
  any: Condition[]
}

export type Condition = LeafCondition | AllCondition | AnyCondition | Record<string, never>

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

class RulesApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = "RulesApiError"
    this.status = status
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  if (!res.ok) {
    const body = await res.text()
    let detail = body
    try {
      const parsed = JSON.parse(body) as { detail?: string }
      if (parsed.detail) detail = parsed.detail
    } catch {
      // use raw text
    }
    throw new RulesApiError(
      `notification-rules-api: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`,
      res.status,
    )
  }
  if (res.status === 204) return undefined as unknown as T
  return res.json() as Promise<T>
}

export async function listRules(orgId: string): Promise<NotificationRule[]> {
  const qs = new URLSearchParams({ org_id: orgId })
  const data = await fetchJson<{ rules: NotificationRule[] }>(`${BASE}?${qs}`)
  return data.rules ?? []
}

export async function createRule(payload: CreateRulePayload): Promise<NotificationRule> {
  return fetchJson<NotificationRule>(BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
}

export async function updateRule(
  id: string,
  orgId: string,
  payload: UpdateRulePayload,
): Promise<NotificationRule> {
  const qs = new URLSearchParams({ org_id: orgId })
  return fetchJson<NotificationRule>(`${BASE}/${id}?${qs}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
}

export async function deleteRule(id: string, orgId: string): Promise<void> {
  const qs = new URLSearchParams({ org_id: orgId })
  await fetchJson<void>(`${BASE}/${id}?${qs}`, { method: "DELETE" })
}

export async function previewRule(req: PreviewSingleRuleRequest): Promise<PreviewSingleResult> {
  return fetchJson<PreviewSingleResult>(`${BASE}/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  })
}

export async function previewOrg(req: PreviewOrgRequest): Promise<PreviewOrgResult> {
  return fetchJson<PreviewOrgResult>(`${BASE}/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  })
}

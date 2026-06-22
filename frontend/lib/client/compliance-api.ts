/** Client for the compliance frameworks and controls surface. */

import { apiClient } from "./api-client.ts"

export interface ComplianceFramework {
  id: string
  label: string
}

export interface FrameworkControl {
  id: number
  framework: string
  control_id: string
  title: string
  description: string | null
  category: string | null
}

export interface ControlSummaryItem {
  framework: string
  control_id: string
  title: string
  category: string | null
  finding_count: number
  highest_severity: string | null
}

export interface FrameworkSummary {
  framework: string
  label: string
  controls: ControlSummaryItem[]
}

export interface ComplianceFindingBrief {
  id: number
  tool: string
  org: string
  repo: string | null
  severity: string | null
  state: string
  identity_key: string
  confidence: number
  rationale: string | null
}

export interface ControlFindingsResponse {
  framework: string
  control_id: string
  findings: ComplianceFindingBrief[]
}

export interface ControlMapping {
  framework: string
  control_id: string
  title: string
  confidence: number
  rationale: string | null
}

export interface FindingControlsResponse {
  finding_id: number
  mappings: ControlMapping[]
}

export async function listFrameworks(): Promise<ComplianceFramework[]> {
  const data = await apiClient<{ frameworks: ComplianceFramework[] }>(
    "/api/v1/compliance/frameworks",
  )
  return data.frameworks
}

export async function listFrameworkControls(framework: string): Promise<FrameworkControl[]> {
  const data = await apiClient<{ controls: FrameworkControl[] }>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/controls`,
  )
  return data.controls
}

export async function getFrameworkSummary(framework: string): Promise<ControlSummaryItem[]> {
  const data = await apiClient<FrameworkSummary>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/summary`,
  )
  return data.controls
}

export async function getControlFindings(
  framework: string,
  controlId: string,
): Promise<ControlFindingsResponse> {
  return apiClient<ControlFindingsResponse>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/controls/${encodeURIComponent(controlId)}/findings`,
  )
}

export async function getFindingControls(
  findingId: number | string,
): Promise<FindingControlsResponse> {
  return apiClient<FindingControlsResponse>(
    `/api/v1/compliance/findings/${encodeURIComponent(String(findingId))}/controls`,
  )
}

export type ControlStatus = "met" | "partial" | "unmet" | "na"

export function deriveControlStatus(c: ControlSummaryItem): ControlStatus {
  if (c.finding_count === 0) return "met"
  if (c.highest_severity === "critical" || c.highest_severity === "high") return "unmet"
  return "partial"
}

export interface FrameworkRecord {
  id: string
  label: string
  description: string | null
  is_custom: boolean
  created_by_user_id: string | null
  created_at: string
  updated_at: string
}

export interface FrameworkControlRecord {
  id: number
  framework: string
  control_id: string
  title: string
  description: string | null
  category: string | null
  is_custom: boolean
  created_by_user_id: string | null
  created_at: string
}

export interface CreateFrameworkBody {
  id: string
  label: string
  description?: string | null
}

export interface CreateControlBody {
  control_id: string
  title: string
  description?: string | null
  category?: string | null
}

export async function createFramework(body: CreateFrameworkBody): Promise<FrameworkRecord> {
  return apiClient<FrameworkRecord>("/api/v1/compliance/frameworks", {
    method: "POST",
    body,
  })
}

export async function deleteFramework(id: string): Promise<void> {
  await apiClient<void>(`/api/v1/compliance/frameworks/${encodeURIComponent(id)}`, {
    method: "DELETE",
  })
}

export async function createFrameworkControl(
  frameworkId: string,
  body: CreateControlBody,
): Promise<FrameworkControlRecord> {
  return apiClient<FrameworkControlRecord>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}/controls`,
    {
      method: "POST",
      body,
    },
  )
}

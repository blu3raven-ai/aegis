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
  control_id: string
  title: string
  category: string | null
  finding_count: number
  chain_count: number
  highest_severity: string | null
}

export interface FrameworkSummary {
  framework: string
  controls: ControlSummaryItem[]
}

export interface ComplianceFindingBrief {
  id: number
  title: string
  severity: string
  scanner_type: string | null
  state: string
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
  return apiClient<ComplianceFramework[]>("/api/v1/compliance/frameworks")
}

export async function listFrameworkControls(framework: string): Promise<FrameworkControl[]> {
  return apiClient<FrameworkControl[]>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/controls`,
  )
}

export async function getFrameworkSummary(framework: string, orgId: string): Promise<ControlSummaryItem[]> {
  const response = await apiClient<FrameworkSummary>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/summary?org_id=${encodeURIComponent(orgId)}`,
  )
  return response.controls
}

export async function getControlFindings(
  framework: string,
  controlId: string,
  orgId: string,
): Promise<ControlFindingsResponse> {
  return apiClient<ControlFindingsResponse>(
    `/api/v1/compliance/controls/${encodeURIComponent(framework)}/${encodeURIComponent(controlId)}/findings?org_id=${encodeURIComponent(orgId)}`,
  )
}

export async function getFindingControls(findingId: number | string): Promise<FindingControlsResponse> {
  return apiClient<FindingControlsResponse>(
    `/api/v1/compliance/findings/${encodeURIComponent(String(findingId))}/controls`,
  )
}

export type ControlStatus = "met" | "partial" | "unmet" | "na"

export function deriveControlStatus(c: ControlSummaryItem): ControlStatus {
  if (c.finding_count === 0 && c.chain_count === 0) return "met"
  if (c.chain_count > 0) return "unmet"
  if (c.highest_severity === "critical" || c.highest_severity === "high") return "unmet"
  return "partial"
}

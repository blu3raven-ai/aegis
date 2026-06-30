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
  // Manual attestation overlay — null until a control is assessed.
  manual_status: ManualControlStatus | null
  evidence_note: string | null
  evidence_url: string | null
  assessed_by: string | null
  assessed_at: string | null
  // Remediation overlay.
  owner_user_id: string | null
  owner_label: string | null
  due_date: string | null
  overdue: boolean
}

export type ManualControlStatus =
  | "compliant"
  | "non_compliant"
  | "in_progress"
  | "not_applicable"

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
  mapping_id: number
  suppressed: boolean
  manual: boolean
}

export interface MappableFinding {
  id: number
  tool: string
  title: string | null
  severity: string | null
  org: string
  repo: string | null
  identity_key: string
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

// A manual attestation, when present, overrides the finding-derived status —
// mirrors the backend's _derive_control_status so UI and exports agree.
const MANUAL_STATUS_TO_STATUS: Record<ManualControlStatus, ControlStatus> = {
  compliant: "met",
  not_applicable: "met",
  in_progress: "partial",
  non_compliant: "unmet",
}

export function deriveControlStatus(c: ControlSummaryItem): ControlStatus {
  if (c.manual_status && c.manual_status in MANUAL_STATUS_TO_STATUS) {
    return MANUAL_STATUS_TO_STATUS[c.manual_status]
  }
  if (c.finding_count === 0) return "met"
  if (c.highest_severity === "critical" || c.highest_severity === "high") return "unmet"
  return "partial"
}

export interface ControlAssessment {
  framework: string
  control_id: string
  status: ManualControlStatus | null
  evidence_note: string | null
  evidence_url: string | null
  owner_user_id: string | null
  due_date: string | null
  assessed_by: string | null
  assessed_at: string | null
}

/** Suppress an auto-generated mapping as a false positive, or restore it. */
export async function setMappingSuppressed(
  mappingId: number,
  body: { suppressed: boolean; reason?: string | null },
): Promise<void> {
  await apiClient<void>(
    `/api/v1/compliance/mappings/${mappingId}`,
    { method: "PATCH", body },
  )
}

/** Search open, in-scope findings not yet mapped to a control — the manual-map picker. */
export async function searchMappableFindings(
  framework: string,
  controlId: string,
  q: string | null = null,
  limit = 20,
): Promise<MappableFinding[]> {
  const qs = new URLSearchParams({ limit: String(limit) })
  const trimmed = q?.trim()
  if (trimmed) qs.set("q", trimmed)
  const data = await apiClient<{ findings: MappableFinding[] }>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/controls/${encodeURIComponent(controlId)}/mappable-findings?${qs.toString()}`,
  )
  return data.findings
}

/** Manually map a finding to a control. `created` is false when it was already mapped. */
export async function createMapping(
  framework: string,
  controlId: string,
  findingId: number,
): Promise<{ mapping_id: number; finding_id: number; created: boolean }> {
  return apiClient<{ mapping_id: number; finding_id: number; created: boolean }>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/controls/${encodeURIComponent(controlId)}/mappings`,
    { method: "POST", body: { finding_id: findingId } },
  )
}

/** Set or clear a control's manual attestation. `status: "auto"` clears it. */
export async function upsertControlAssessment(
  framework: string,
  controlId: string,
  body: {
    status: ManualControlStatus | "auto"
    evidence_note?: string | null
    evidence_url?: string | null
    owner_user_id?: string | null
    due_date?: string | null
  },
): Promise<ControlAssessment> {
  return apiClient<ControlAssessment>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/controls/${encodeURIComponent(controlId)}/assessment`,
    { method: "PUT", body },
  )
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

export interface CreateFrameworkWithControlsBody extends CreateFrameworkBody {
  controls: CreateControlBody[]
}

/** Create a framework and its controls atomically — nothing persists unless the
 *  whole batch validates, so a failed submit can be cleanly retried. */
export async function createFrameworkWithControls(
  body: CreateFrameworkWithControlsBody,
): Promise<FrameworkRecord> {
  return apiClient<FrameworkRecord>("/api/v1/compliance/frameworks/with-controls", {
    method: "POST",
    body,
  })
}

export async function deleteFramework(id: string): Promise<void> {
  await apiClient<void>(`/api/v1/compliance/frameworks/${encodeURIComponent(id)}`, {
    method: "DELETE",
  })
}

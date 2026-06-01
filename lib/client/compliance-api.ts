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
  const res = await fetch("/api/v1/compliance/frameworks")
  if (!res.ok) throw new Error(`Failed to fetch frameworks: ${res.status}`)
  return res.json()
}

export async function listFrameworkControls(framework: string): Promise<FrameworkControl[]> {
  const res = await fetch(`/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/controls`)
  if (!res.ok) throw new Error(`Failed to fetch controls: ${res.status}`)
  return res.json()
}

export async function getFrameworkSummary(framework: string, orgId?: string): Promise<ControlSummaryItem[]> {
  const url = orgId
    ? `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/summary?org_id=${encodeURIComponent(orgId)}`
    : `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/summary`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`Failed to fetch framework summary: ${res.status}`)
  return res.json()
}

export async function getControlFindings(
  framework: string,
  controlId: string,
  orgId?: string,
): Promise<ControlFindingsResponse> {
  const url = orgId
    ? `/api/v1/compliance/controls/${encodeURIComponent(framework)}/${encodeURIComponent(controlId)}/findings?org_id=${encodeURIComponent(orgId)}`
    : `/api/v1/compliance/controls/${encodeURIComponent(framework)}/${encodeURIComponent(controlId)}/findings`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`Failed to fetch control findings: ${res.status}`)
  return res.json()
}

export async function getFindingControls(findingId: number | string): Promise<FindingControlsResponse> {
  const res = await fetch(`/api/v1/compliance/findings/${encodeURIComponent(String(findingId))}/controls`)
  if (!res.ok) throw new Error(`Failed to fetch finding controls: ${res.status}`)
  return res.json()
}

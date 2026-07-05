const TYPE_LABELS: Record<string, string> = {
  "finding.created": "New findings",
  "finding.dismissed": "Dismissed",
  "finding.fixed": "Fixed",
  "finding.reopened": "Reopened",
  "scan.completed": "Scans",
  "scan.failed": "Failed scans",
  "scan.cancelled": "Cancelled scans",
  "intel.cve.added": "CVE added",
  "kev.added": "KEV added",
  "sla.breached": "SLA breached",
  "integration.connected": "Integration connected",
  "integration.disconnected": "Integration disconnected",
}

export function eventTypeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type
}

export const CHIP_GROUPS: { id: string; label: string; types: string[] }[] = [
  { id: "all", label: "All", types: [] },
  { id: "findings", label: "Findings", types: ["finding.created", "finding.fixed", "finding.dismissed", "finding.reopened"] },
  { id: "scans", label: "Scans", types: ["scan.completed", "scan.failed", "scan.cancelled"] },
  { id: "intel", label: "Intel", types: ["intel.cve.added", "kev.added", "sla.breached"] },
  { id: "integrations", label: "Integrations", types: ["integration.connected", "integration.disconnected"] },
]

export function chipTypesFor(chipId: string): string[] {
  return CHIP_GROUPS.find((c) => c.id === chipId)?.types ?? []
}

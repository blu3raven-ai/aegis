const TYPE_LABELS: Record<string, string> = {
  "finding.created": "New findings",
  "finding.dismissed": "Dismissed",
  "finding.fixed": "Fixed",
  "finding.reopened": "Reopened",
  "scan.completed": "Scans",
  "scan.failed": "Failed scans",
  "integration.connected": "Integrations",
  "integration.disconnected": "Disconnected",
  "intel.cve.added": "CVE intel",
  "sla.breached": "SLA breaches",
  "kev.added": "KEV updates",
}

export function eventTypeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type
}

export const CHIP_GROUPS = [
  { id: "all", label: "All", types: [] as string[], disabled: false },
  { id: "findings", label: "Findings", types: ["finding.created", "finding.fixed", "finding.reopened"], disabled: false },
  { id: "scans", label: "Scans", types: ["scan.completed", "scan.failed"], disabled: false },
  { id: "decisions", label: "Decisions", types: ["finding.dismissed"], disabled: false },
  { id: "intel", label: "Intel", types: ["intel.cve.added", "kev.added", "sla.breached"], disabled: false },
  { id: "integrations", label: "Integrations", types: ["integration.connected", "integration.disconnected"], disabled: false },
] as const

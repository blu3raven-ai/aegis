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

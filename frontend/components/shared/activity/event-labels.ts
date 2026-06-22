const TYPE_LABELS: Record<string, string> = {
  "finding.created": "New findings",
  "finding.dismissed": "Dismissed",
  "finding.fixed": "Fixed",
  "finding.reopened": "Reopened",
  "scan.completed": "Scans",
  "scan.failed": "Failed scans",
  "scan.cancelled": "Cancelled scans",
}

export function eventTypeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type
}

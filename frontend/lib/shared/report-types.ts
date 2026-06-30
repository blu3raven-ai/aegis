/**
 * Single source of truth for report types, their human labels, and which output
 * formats each supports. Shared by the on-demand generate form and the scheduled
 * report modal so the two surfaces can't drift (and so a format can never be left
 * stranded as invalid for the selected type). Mirrors the backend
 * GenerateReportRequest / ScheduledReportCreate enums.
 */

export type ReportType =
  | "findings"
  | "posture"
  | "executive"
  | "risk_register"
  | "soc2_evidence"

export type ReportFormat = "json" | "csv" | "pdf" | "zip"

export const REPORT_TYPE_OPTIONS: { id: ReportType; label: string }[] = [
  { id: "findings", label: "Findings" },
  { id: "posture", label: "Posture" },
  { id: "executive", label: "Executive" },
  { id: "risk_register", label: "Risk register" },
  { id: "soc2_evidence", label: "SOC 2 evidence" },
]

const FORMAT_LABEL: Record<ReportFormat, string> = {
  csv: "CSV",
  json: "JSON",
  pdf: "PDF",
  zip: "ZIP",
}

// Default-first order per type — the first entry is the default when the current
// format isn't valid for a newly-selected type. Matches the backend's accepted
// (report_type, format) pairs.
export const FORMATS_BY_TYPE: Record<ReportType, ReportFormat[]> = {
  findings: ["csv", "json", "pdf"],
  posture: ["json", "pdf"],
  executive: ["pdf"],
  risk_register: ["pdf", "csv"],
  soc2_evidence: ["zip"],
}

export function formatOptionsForType(type: ReportType): { id: ReportFormat; label: string }[] {
  return FORMATS_BY_TYPE[type].map((id) => ({ id, label: FORMAT_LABEL[id] }))
}

/** Keep `current` if it's valid for `type`, otherwise snap to the type's default. */
export function clampFormat(type: ReportType, current: ReportFormat): ReportFormat {
  return FORMATS_BY_TYPE[type].includes(current) ? current : FORMATS_BY_TYPE[type][0]
}

const TYPE_LABEL: Record<string, string> = Object.fromEntries(
  REPORT_TYPE_OPTIONS.map((o) => [o.id, o.label]),
)

/** Human label for a report_type; degrades gracefully for unknown values. */
export function reportTypeLabel(type: string): string {
  return TYPE_LABEL[type] ?? type.replace(/_/g, " ")
}

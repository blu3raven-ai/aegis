/**
 * Shared display helpers for rule actions.
 *
 * Renders the right-hand side of the "condition → action" line that
 * appears in RuleRow. Extracted so the SLA and scanner-coverage action
 * shapes can be summarised side-by-side without piling category checks
 * into the row component.
 */

import {
  isSlaAction,
  isRequireScannersAction,
  isStaleAlertAction,
  isArchiveAction,
  isDeleteAction,
  type RuleAction,
} from "@/lib/client/rules-api"

const SCANNER_LABELS: Record<string, string> = {
  dependencies: "SCA",
  code_scanning: "SAST",
  container_scanning: "Containers",
  secrets: "Secrets",
}

export function summarizeAction(action: RuleAction): string {
  if (isSlaAction(action)) {
    const base = `Fix within ${action.deadline_days} day${action.deadline_days === 1 ? "" : "s"}`
    const escalations = action.escalations ?? []
    if (escalations.length === 0) return base
    const first = escalations[0]
    const channelCount = escalations.length
    const channelLabel = channelCount === 1 ? "1 channel" : `${channelCount} channels`
    return `${base} · escalate at ${first.at_hours}h to ${channelLabel}`
  }
  if (isRequireScannersAction(action)) {
    if (action.required_scanners.length === 0) return "no scanners required"
    return action.required_scanners.map((s) => SCANNER_LABELS[s] ?? s).join(" · ") + " required"
  }
  if (isStaleAlertAction(action)) {
    const trigger = `Alert when scan is older than ${action.stale_after_days} day${action.stale_after_days === 1 ? "" : "s"}`
    return action.auto_retrigger ? `${trigger} (auto re-scan)` : trigger
  }
  if (isArchiveAction(action)) {
    return `Archive after ${action.after_days} day${action.after_days === 1 ? "" : "s"} · keep retrievable`
  }
  if (isDeleteAction(action)) {
    return `Delete after ${action.after_days} day${action.after_days === 1 ? "" : "s"} · permanent`
  }
  return "—"
}

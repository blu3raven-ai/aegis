import type { ActivityEvent } from "@/lib/client/activity-api"

export interface DayStats {
  total: number
  newFindings: number
  criticalFindings: number
  fixed: number
  decisions: number
  scans: number
  byType: Record<string, number>
}

export interface CatchUpData {
  since: string
  total: number
  newFindings: number
  criticalFindings: number
  fixed: number
}

function isCriticalFinding(e: ActivityEvent): boolean {
  if (e.type !== "finding.created") return false
  const severity = (e.payload as { severity?: unknown }).severity
  return severity === "critical"
}

/**
 * Derive aggregate stats from a window of pre-filtered events.
 * Caller is expected to pre-scope the events with `listActivity({ since })`
 * before passing them in — this function does not filter by time.
 */
export function deriveDayStats(events: ActivityEvent[]): DayStats {
  const byType: Record<string, number> = {}
  for (const e of events) {
    byType[e.type] = (byType[e.type] || 0) + 1
  }
  return {
    total: events.length,
    newFindings: events.filter((e) => e.type === "finding.created").length,
    criticalFindings: events.filter(isCriticalFinding).length,
    fixed: events.filter((e) => e.type === "finding.fixed").length,
    decisions: events.filter((e) => e.type === "finding.dismissed").length,
    scans: events.filter((e) => e.type.startsWith("scan.")).length,
    byType,
  }
}

/**
 * Derive a catch-up summary for the notification drawer banner.
 * Caller is expected to pre-scope `events` to the window `[since, now]` via
 * `listActivity({ since })`; this function does not filter by time. The
 * `since` argument is echoed back into the returned object so the banner can
 * render "Away since <relative time>".
 */
export function deriveCatchUp(events: ActivityEvent[], since: string): CatchUpData {
  return {
    since,
    total: events.length,
    newFindings: events.filter((e) => e.type === "finding.created").length,
    criticalFindings: events.filter(isCriticalFinding).length,
    fixed: events.filter((e) => e.type === "finding.fixed").length,
  }
}

/**
 * Shared formatting + style helpers for release verdict UI.
 *
 * Centralised here because diff-status pill classes are reused across
 * BlockerDiffList, ImprovementsList, and RecentReleaseChecksTable — any
 * drift between them would break visual parity for the same finding.
 */

import type { BlockerDiffRow } from "@/lib/client/releases-api"

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—"
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 2) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export const DIFF_PILL_BASE =
  "inline-flex items-center justify-center rounded-full px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.14em]"

export const DIFF_PILL_VARIANT: Record<BlockerDiffRow["diff_status"], string> = {
  new:       "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
  persisted: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]",
  gone:      "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]",
  fixed:     "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]",
}

export const SEVERITY_LETTER: Record<string, string> = {
  critical: "C",
  high:     "H",
  medium:   "M",
  low:      "L",
  info:     "I",
}

export const SEVERITY_TONE: Record<string, string> = {
  critical: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
  high:     "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high)]",
  medium:   "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium)]",
  low:      "bg-[var(--color-surface-raised)] text-[var(--color-severity-low)]",
  info:     "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]",
}

export function severityKey(severity: string): string {
  const key = severity.toLowerCase()
  if (key in SEVERITY_LETTER) return key
  return "info"
}

export function shortenSha(sha: string | null | undefined): string {
  if (!sha) return ""
  return sha.length > 7 ? sha.slice(0, 7) : sha
}

const DIFF_ORDER: Record<BlockerDiffRow["diff_status"], number> = {
  new:       0,
  persisted: 1,
  gone:      2,
  fixed:     3,
}

export function sortByDiffStatus(rows: BlockerDiffRow[]): BlockerDiffRow[] {
  return [...rows].sort(
    (a, b) => DIFF_ORDER[a.diff_status] - DIFF_ORDER[b.diff_status],
  )
}

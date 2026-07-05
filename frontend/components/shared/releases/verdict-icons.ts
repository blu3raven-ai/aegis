import type { ReleaseSummary } from "@/lib/client/releases-api"

export type Verdict = ReleaseSummary["verdict"]

export interface VerdictIcon {
  glyph: string
  tone: string
}

/**
 * Compact verdict indicator (glyph + semantic tone) shared by the releases
 * table and the releases page header so the two never drift apart.
 */
export const VERDICT_ICONS: Record<Verdict, VerdictIcon> = {
  go:      { glyph: "✓", tone: "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok-text)]" },
  no_go:   { glyph: "×", tone: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]" },
  warn:    { glyph: "!", tone: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]" },
  pending: { glyph: "•", tone: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]" },
  unknown: { glyph: "—", tone: "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]" },
}

/**
 * Pill badge showing repo scan coverage status: fresh / stale / never.
 * Uses existing color tokens — no new design tokens introduced.
 */

const STATUS_STYLES = {
  fresh:  "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]",
  stale:  "border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]",
  never:  "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
} as const

const STATUS_DOT = {
  fresh: "bg-[var(--color-status-ok)]",
  stale: "bg-[var(--color-state-pending)]",
  never: "bg-[var(--color-text-secondary)]",
} as const

const STATUS_LABEL = {
  fresh: "Fresh",
  stale: "Stale",
  never: "Never scanned",
} as const

interface RepoCoverageBadgeProps {
  status: "fresh" | "stale" | "never"
}

export function RepoCoverageBadge({ status }: RepoCoverageBadgeProps) {
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-medium ${STATUS_STYLES[status]}`}
    >
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${STATUS_DOT[status]}`} />
      {STATUS_LABEL[status]}
    </span>
  )
}

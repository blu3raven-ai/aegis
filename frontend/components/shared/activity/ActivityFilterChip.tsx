"use client"

export { eventTypeLabel } from "./event-labels"

interface ActivityFilterChipProps {
  label: string
  active: boolean
  onToggle: () => void
}

export function ActivityFilterChip({ label, active, onToggle }: ActivityFilterChipProps) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={active}
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
        active
          ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
          : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
      }`}
    >
      {label}
    </button>
  )
}

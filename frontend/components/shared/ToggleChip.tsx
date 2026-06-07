
const ACTIVE_COLORS = {
  accent:  "border-[var(--color-accent-border)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
  emerald: "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]",
} as const

const INACTIVE = "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"

interface ToggleChipProps {
  label: string
  active: boolean
  onClick: () => void
  activeColor?: keyof typeof ACTIVE_COLORS
}

export function ToggleChip({ label, active, onClick, activeColor = "accent" }: ToggleChipProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors cursor-pointer ${
        active ? ACTIVE_COLORS[activeColor] : INACTIVE
      }`}
    >
      {label}
    </button>
  )
}

import type { ReactNode } from "react"
import { cn } from "@/lib/shared/utils"

interface FilterChipProps {
  label: ReactNode
  active: boolean
  onClick: () => void
  count?: number
  icon?: ReactNode
  tone?: "accent" | "success" | "danger"
  ariaLabel?: string
  className?: string
  disabled?: boolean
}

const toneActive: Record<NonNullable<FilterChipProps["tone"]>, string> = {
  accent:
    "border-[var(--color-accent-border)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
  success:
    "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]",
  danger:
    "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
}

export function FilterChip({
  label,
  active,
  onClick,
  count,
  icon,
  tone = "accent",
  ariaLabel,
  className,
  disabled,
}: FilterChipProps) {
  return (
    <button
      type="button"
      aria-pressed={active}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={onClick}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-xs font-semibold transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1 focus-visible:ring-offset-[var(--color-surface)]",
        "disabled:cursor-not-allowed disabled:opacity-50",
        active
          ? toneActive[tone]
          : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)]",
        className,
      )}
    >
      {icon && <span className="h-3.5 w-3.5 shrink-0">{icon}</span>}
      <span>{label}</span>
      {typeof count === "number" && (
        <span
          className={cn(
            "ml-0.5 rounded-full px-1.5 text-2xs tabular-nums",
            active ? "bg-current/15" : "bg-[var(--color-bg-section)] text-[var(--color-text-tertiary)]",
          )}
        >
          {count}
        </span>
      )}
    </button>
  )
}

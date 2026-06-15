import type { ReactNode } from "react"
import { cn } from "@/lib/shared/utils"

export interface SegmentedOption<T extends string> {
  id: T
  label: string
  icon?: ReactNode
  count?: number
  disabled?: boolean
}

interface SegmentedControlProps<T extends string> {
  options: readonly SegmentedOption<T>[]
  value: T
  onChange: (id: T) => void
  size?: "xs" | "sm" | "md"
  ariaLabel?: string
  className?: string
}

const sizeClasses = {
  xs: "h-6 px-2 text-2xs",
  sm: "h-7 px-2.5 text-xs",
  md: "h-8 px-3 text-xs",
} as const

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  size = "sm",
  ariaLabel,
  className,
}: SegmentedControlProps<T>) {
  const sizing = sizeClasses[size]

  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className={cn(
        "inline-flex items-center rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-px",
        className,
      )}
    >
      {options.map((opt) => {
        const active = opt.id === value
        return (
          <button
            key={opt.id}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={opt.disabled}
            onClick={() => onChange(opt.id)}
            className={cn(
              "inline-flex items-center justify-center gap-1.5 rounded font-semibold transition-colors",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1 focus-visible:ring-offset-[var(--color-surface)]",
              "disabled:cursor-not-allowed disabled:opacity-50",
              sizing,
              active
                ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]",
            )}
          >
            {opt.icon && <span className="h-3.5 w-3.5 shrink-0">{opt.icon}</span>}
            <span>{opt.label}</span>
            {typeof opt.count === "number" && (
              <span
                className={cn(
                  "rounded-full px-1.5 text-2xs tabular-nums",
                  active
                    ? "bg-current/20"
                    : "bg-[var(--color-bg-section)] text-[var(--color-text-tertiary)]",
                )}
              >
                {opt.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

import type { ReactNode } from "react"
import { cn } from "@/lib/shared/utils"

/**
 * Canonical status / severity tones. Each maps to a subtle background AND an
 * AA-safe text colour, both theme-aware, so a badge reads correctly in light and
 * dark without the caller hand-picking tokens. This is the single source of
 * truth: using a *fill* token (e.g. `--color-severity-critical`) as text — the
 * recurring low-contrast bug — is impossible through this component or the
 * `statusTextClass` helper.
 */
export type StatusTone =
  | "neutral"
  | "ok"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "pending"
  | "fixed"
  | "info"

const TONE_BG: Record<StatusTone, string> = {
  neutral: "bg-[var(--color-border-strong)]",
  ok: "bg-[var(--color-status-ok-subtle)]",
  critical: "bg-[var(--color-severity-critical-subtle)]",
  high: "bg-[var(--color-severity-high-subtle)]",
  medium: "bg-[var(--color-severity-medium-subtle)]",
  low: "bg-[var(--color-severity-low-subtle)]",
  pending: "bg-[var(--color-state-pending-subtle)]",
  fixed: "bg-[var(--color-state-fixed-subtle)]",
  info: "bg-[var(--color-accent-subtle)]",
}

const TONE_TEXT: Record<StatusTone, string> = {
  neutral: "text-[var(--color-text-secondary)]",
  ok: "text-[var(--color-status-ok-text)]",
  critical: "text-[var(--color-severity-critical-text)]",
  high: "text-[var(--color-severity-high-text)]",
  medium: "text-[var(--color-severity-medium-text)]",
  low: "text-[var(--color-severity-low-text)]",
  pending: "text-[var(--color-state-pending-text)]",
  fixed: "text-[var(--color-state-fixed-text)]",
  info: "text-[var(--color-accent)]",
}

/** The AA-safe text colour class for a tone. Use for inline status text (an
 *  error/success message, a coloured label) that isn't a pill. */
export function statusTextClass(tone: StatusTone): string {
  return TONE_TEXT[tone]
}

interface StatusBadgeProps {
  tone?: StatusTone
  children: ReactNode
  /** Compact 10px uppercase caps chip (e.g. "CURRENT") instead of the default pill. */
  caps?: boolean
  className?: string
}

/** A status/severity pill with the correct subtle-fill + readable-text pairing
 *  for both themes. Prefer this over hand-rolled `bg-…/text-…` status spans. */
export function StatusBadge({ tone = "neutral", children, caps = false, className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full font-medium",
        caps
          ? "px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-[0.08em]"
          : "px-2 py-0.5 text-xs",
        TONE_BG[tone],
        TONE_TEXT[tone],
        className,
      )}
    >
      {children}
    </span>
  )
}

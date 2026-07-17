"use client"

export interface FindingsGroupHeaderProps {
  label: string
  severityCounts: { critical: number; high: number; medium: number; low: number }
  total: number
  expanded: boolean
  onToggle: () => void
}

const SEV_TOKENS: Record<keyof FindingsGroupHeaderProps["severityCounts"], { bg: string; fg: string; abbr: string }> = {
  critical: { bg: "bg-[var(--color-severity-critical-subtle)]", fg: "text-[var(--color-severity-critical-text)]", abbr: "crit" },
  high:     { bg: "bg-[var(--color-severity-high-subtle)]",     fg: "text-[var(--color-severity-high-text)]",     abbr: "high" },
  medium:   { bg: "bg-[var(--color-severity-medium-subtle)]",   fg: "text-[var(--color-severity-medium-text)]",   abbr: "med" },
  low:      { bg: "bg-[var(--color-severity-low-subtle)]",      fg: "text-[var(--color-severity-low-text)]",      abbr: "low" },
}

export function FindingsGroupHeader({
  label,
  severityCounts,
  total,
  expanded,
  onToggle,
}: FindingsGroupHeaderProps) {
  return (
    <button
      type="button"
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          onToggle()
        }
      }}
      aria-expanded={expanded}
      className="flex w-full items-center justify-between px-4 py-2 bg-[var(--color-bg-section)] text-left hover:bg-[var(--color-bg-hover)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset"
    >
      <span className="flex items-center gap-2 font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
        <svg
          width="10"
          height="10"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          className={`transition-transform ${expanded ? "rotate-0" : "-rotate-90"}`}
          aria-hidden="true"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
        {label}
      </span>
      <span className="flex items-center gap-2">
        {severityCounts.critical > 0 && (
          <span className={`${SEV_TOKENS.critical.bg} ${SEV_TOKENS.critical.fg} rounded-sm px-1.5 py-0.5 text-2xs font-semibold`}>
            {severityCounts.critical} {SEV_TOKENS.critical.abbr}
          </span>
        )}
        {severityCounts.high > 0 && (
          <span className={`${SEV_TOKENS.high.bg} ${SEV_TOKENS.high.fg} rounded-sm px-1.5 py-0.5 text-2xs font-semibold`}>
            {severityCounts.high} {SEV_TOKENS.high.abbr}
          </span>
        )}
        {severityCounts.medium > 0 && (
          <span className={`${SEV_TOKENS.medium.bg} ${SEV_TOKENS.medium.fg} rounded-sm px-1.5 py-0.5 text-2xs font-semibold`}>
            {severityCounts.medium} {SEV_TOKENS.medium.abbr}
          </span>
        )}
        {severityCounts.low > 0 && (
          <span className={`${SEV_TOKENS.low.bg} ${SEV_TOKENS.low.fg} rounded-sm px-1.5 py-0.5 text-2xs font-semibold`}>
            {severityCounts.low} {SEV_TOKENS.low.abbr}
          </span>
        )}
        <span className="text-[11px] font-medium tabular-nums normal-case tracking-normal text-[var(--color-text-secondary)]">
          {total} {total === 1 ? "finding" : "findings"}
        </span>
      </span>
    </button>
  )
}

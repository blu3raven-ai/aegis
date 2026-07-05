interface SeverityCountsProps {
  counts: {
    critical: number
    high: number
    medium: number
    low?: number
  }
  emptyLabel?: string
  includeLow?: boolean
}

export function SeverityCounts({
  counts,
  emptyLabel = "no open findings",
  includeLow = false,
}: SeverityCountsProps) {
  const items = [
    { count: counts.critical, label: "crit", color: "text-[var(--color-severity-critical-text)]", dot: "bg-[var(--color-severity-critical)]" },
    { count: counts.high,     label: "high", color: "text-[var(--color-severity-high-text)]",     dot: "bg-[var(--color-severity-high)]"     },
    { count: counts.medium,   label: "med",  color: "text-[var(--color-severity-medium-text)]",   dot: "bg-[var(--color-severity-medium)]"   },
    ...(includeLow && counts.low != null
      ? [{ count: counts.low, label: "low", color: "text-[var(--color-severity-low-text)]", dot: "bg-[var(--color-severity-low)]" }]
      : []),
  ]
  const visible = items.filter((i) => i.count > 0)
  if (visible.length === 0) {
    return (
      <span className="text-xs italic text-[var(--color-text-tertiary)]">{emptyLabel}</span>
    )
  }
  return (
    <div className="flex items-center gap-3">
      {visible.map((item) => (
        <span key={item.label} className="flex items-center gap-1 text-xs tabular-nums">
          <span className={`h-1.5 w-1.5 rounded-full ${item.dot}`} aria-hidden="true" />
          <span className={`font-semibold ${item.color}`}>{item.count}</span>
          <span className="text-[var(--color-text-secondary)]">{item.label}</span>
        </span>
      ))}
    </div>
  )
}

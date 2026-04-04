export function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl bg-[var(--color-surface-raised)] p-4">
      <p className="text-xs font-medium uppercase tracking-[0.10em] text-[var(--color-text-secondary)]">{label}</p>
      <p className="mt-2 text-2xl font-semibold leading-tight text-[var(--color-text-primary)]">{value}</p>
    </div>
  )
}

export function formatDays(value: number | null | undefined): string {
  if (value == null) return "N/A"
  if (value < 1) return "< 1 day"
  const rounded = Number.isInteger(value) ? value : Math.round(value * 10) / 10
  return `${rounded} ${rounded === 1 ? "day" : "days"}`
}

export function formatCount(value: number | null | undefined): string {
  if (value == null) return "\u2014"
  return String(value)
}

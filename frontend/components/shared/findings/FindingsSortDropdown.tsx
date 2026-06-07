"use client"

export type SortKey = "severity_age" | "epss" | "risk_score" | "newest" | "oldest"

export const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: "severity_age", label: "Severity → Age" },
  { value: "epss",         label: "EPSS (high → low)" },
  { value: "risk_score",   label: "Risk score (high → low)" },
  { value: "newest",       label: "Newest" },
  { value: "oldest",       label: "Oldest" },
]

export interface FindingsSortDropdownProps {
  value: SortKey
  onChange: (next: SortKey) => void
}

export function FindingsSortDropdown({ value, onChange }: FindingsSortDropdownProps) {
  return (
    <label className="inline-flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
      <span className="text-2xs font-semibold uppercase tracking-[0.14em]">Sort</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as SortKey)}
        className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-xs text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
      >
        {SORT_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>
    </label>
  )
}

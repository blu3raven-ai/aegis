"use client"

import { Select } from "@/components/ui/Select"

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
      <Select
        size="sm"
        value={value}
        onChange={(e) => onChange(e.target.value as SortKey)}
        className="w-auto"
      >
        {SORT_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </Select>
    </label>
  )
}
